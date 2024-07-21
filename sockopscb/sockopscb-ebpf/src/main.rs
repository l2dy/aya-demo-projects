#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, BPF_SOCK_OPS_TIMEOUT_INIT, BPF_TCP_SYN_SENT},
    macros::{map, sock_ops, xdp},
    maps::RingBuf,
    programs::{SockOpsContext, XdpContext},
};
use aya_log_ebpf::warn;
use sockopscb_common::{PacketDirection, TcpHandshakeEvent};

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[map]
static TCPHSEVENTS: RingBuf = RingBuf::with_byte_size(1 << 14, 0); // 1 * 16 KiB page size

#[xdp]
pub fn probe_tcp_synack(ctx: XdpContext) -> u32 {
    match try_probe_tcp_synack(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_probe_tcp_synack(ctx: XdpContext) -> Result<u32, ()> {
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

    let mut entry = match TCPHSEVENTS.reserve::<TcpHandshakeEvent>(0) {
        Some(entry) => entry,
        None => {
            warn!(&ctx, "ring buffer is full");
            return Ok(xdp_action::XDP_PASS);
        }
    };
    let event = entry.as_mut_ptr();
    unsafe {
        (*event).peer_addr = source_addr;
        (*event).peer_port = source_port;
        (*event).local_addr = destination_addr;
        (*event).local_port = destination_port;
        (*event).seq = ack_seq - 1;
        (*event).direction = PacketDirection::RX;
    }
    entry.submit(0);

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

// TCP connect

#[sock_ops]
pub fn probe_tcp_connect(ctx: SockOpsContext) -> u32 {
    // BPF_SOCK_OPS_TCP_CONNECT_CB does not expose `write_seq` yet.
    if ctx.op() == BPF_SOCK_OPS_TIMEOUT_INIT {
        let _ = try_probe_tcp_connect(ctx);
    }

    0 // <=0 to use default RTO
}

const AF_INET: u32 = 2;

fn try_probe_tcp_connect(ctx: SockOpsContext) -> Result<u32, u32> {
    if unsafe { (*ctx.ops).state } != BPF_TCP_SYN_SENT {
        return Ok(0);
    }
    if ctx.family() != AF_INET {
        return Ok(0);
    }

    let source_addr = u32::from_be(ctx.local_ip4());
    let source_port = ctx.local_port() as u16; // local_port is stored in host byte order.
    let destination_addr = u32::from_be(ctx.remote_ip4());
    let destination_port = u32::from_be(ctx.remote_port()) as u16;
    let seq = unsafe { (*ctx.ops).snd_nxt };

    let mut entry = match TCPHSEVENTS.reserve::<TcpHandshakeEvent>(0) {
        Some(entry) => entry,
        None => {
            warn!(&ctx, "ring buffer is full");
            return Ok(0);
        }
    };
    let event = entry.as_mut_ptr();
    unsafe {
        (*event).peer_addr = destination_addr;
        (*event).peer_port = destination_port;
        (*event).local_addr = source_addr;
        (*event).local_port = source_port;
        (*event).seq = seq;
        (*event).direction = PacketDirection::TX;
    }
    entry.submit(0);

    Ok(0)
}
