use std::net::Ipv4Addr;

use anyhow::Context;
use aya::maps::AsyncPerfEventArray;
use aya::programs::{TracePoint, Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{debug, info, warn};
use sockstatetp_common::{PacketDirection, TcpHandshakeEvent};
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/sockstatetp"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/sockstatetp"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("sockstatetp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
           .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // Tracepoint
    let tp_sock_state_program: &mut TracePoint =
        bpf.program_mut("inet_sock_set_state").unwrap().try_into()?;
    tp_sock_state_program.load()?;
    tp_sock_state_program
        .attach("sock", "inet_sock_set_state")
        .context("failed to attach the tracepoint program")?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("TCPHSEVENTS").unwrap())?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let event_ptr = buf.as_ptr() as *const TcpHandshakeEvent;
                    let event = unsafe { event_ptr.read_unaligned() };

                    // Host byte order, only supports LE systems!
                    debug!(
                        "{}, Source {}:{}, Peer {}:{}",
                        match event.direction {
                            PacketDirection::TX => "TX",
                            PacketDirection::RX => "RX",
                        },
                        Ipv4Addr::from(event.local_addr),
                        event.local_port,
                        Ipv4Addr::from(event.peer_addr),
                        event.peer_port
                    );
                }
            }

            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
