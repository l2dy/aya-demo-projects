#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, BPF_TCP_SYN_SENT},
    cty::c_ushort,
    macros::{map, tracepoint, xdp},
    maps::PerfEventArray,
    programs::{TracePointContext, XdpContext},
};
use aya_log_ebpf::warn;
use sockstatetp_common::{PacketDirection, TcpHandshakeEvent};

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[map]
static TCPHSEVENTS: PerfEventArray<TcpHandshakeEvent> = PerfEventArray::with_max_entries(1024, 0);

#[xdp]
pub fn sockstatetp(ctx: XdpContext) -> u32 {
    match try_sockstatetp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_sockstatetp(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let destination_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let (source_port, destination_port, ack_seq) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            unsafe {
                if (*tcphdr).syn() == 0 || (*tcphdr).ack() == 0 {
                    return Ok(xdp_action::XDP_PASS);
                }
            }

            (
                u16::from_be(unsafe { (*tcphdr).source }),
                u16::from_be(unsafe { (*tcphdr).dest }),
                u32::from_be(unsafe { (*tcphdr).ack_seq }),
            )
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let event = TcpHandshakeEvent {
        peer_addr: source_addr,
        peer_port: source_port,
        local_addr: destination_addr,
        local_port: destination_port,
        seq: ack_seq - 1,
        direction: PacketDirection::RX,
    };
    TCPHSEVENTS.output(&ctx, &event, 0);

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// Trace TCP state

#[tracepoint(name = "inet_sock_set_state", category = "sock")]
pub fn inet_sock_set_state(ctx: TracePointContext) -> i32 {
    match try_inet_sock_set_state(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

const AF_INET: c_ushort = 2;

// Offsets from /sys/kernel/debug/tracing/events/sock/inet_sock_set_state
const NEW_STATE_OFFSET: usize = 20;
const SPORT_OFFSET: usize = 24;
const DPORT_OFFSET: usize = 26;
const FAMILY_OFFSET: usize = 28;
const SADDR_OFFSET: usize = 32;
const DADDR_OFFSET: usize = 36;

pub fn try_inet_sock_set_state(ctx: TracePointContext) -> Result<i32, i32> {
    match unsafe { ctx.read_at(NEW_STATE_OFFSET) } {
        Ok(BPF_TCP_SYN_SENT) => (),
        Ok(_) => return Ok(0),
        Err(errno) => return Err(errno as i32),
    };

    match unsafe { ctx.read_at(FAMILY_OFFSET) } {
        Ok(AF_INET) => (),
        Ok(_) => return Ok(0),
        Err(errno) => return Err(errno as i32),
    }

    let source_port = match unsafe { ctx.read_at(SPORT_OFFSET) } {
        Ok(port) => port,
        Err(errno) => return Err(errno as i32),
    };
    let destination_port = match unsafe { ctx.read_at(DPORT_OFFSET) } {
        Ok(port) => port,
        Err(errno) => return Err(errno as i32),
    };
    let source_addr = u32::from_be(match unsafe { ctx.read_at(SADDR_OFFSET) } {
        Ok(addr) => addr,
        Err(errno) => return Err(errno as i32),
    });
    let destination_addr = u32::from_be(match unsafe { ctx.read_at(DADDR_OFFSET) } {
        Ok(addr) => addr,
        Err(errno) => return Err(errno as i32),
    });

    let event = TcpHandshakeEvent {
        peer_addr: destination_addr,
        peer_port: destination_port,
        local_addr: source_addr,
        local_port: source_port,
        seq: 0,
        direction: PacketDirection::TX,
    };
    TCPHSEVENTS.output(&ctx, &event, 0);

    Ok(0)
}
