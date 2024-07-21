use std::net::Ipv4Addr;

use anyhow::Context;
use aya::maps::RingBuf;
use aya::programs::{SockOps, Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use sockopscb_common::{PacketDirection, TcpHandshakeEvent};
use tokio::io::unix::AsyncFd;
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long, default_value = "/sys/fs/cgroup/unified")]
    cgroup_path: String,
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
        "../../target/bpfel-unknown-none/debug/sockopscb"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/sockopscb"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("probe_tcp_synack").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
           .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let program: &mut SockOps = bpf.program_mut("probe_tcp_connect").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    program.load()?;
    program.attach(cgroup)?;

    task::spawn(async move {
        let map = bpf.map_mut("TCPHSEVENTS").unwrap();
        let ring_buf = RingBuf::try_from(map)?;
        let mut async_ring_buf = AsyncFd::new(ring_buf)?;

        loop {
            let mut guard = async_ring_buf.readable_mut().await?;
            let entry = guard.get_inner_mut();
            while let Some(event) = entry.next() {
                let event_ptr = event.as_ptr() as *const TcpHandshakeEvent;
                let event = unsafe { event_ptr.read_unaligned() };

                debug!(
                    "{}, peer {}:{}, local {}:{}, seq {}",
                    match event.direction {
                        PacketDirection::TX => "Sent SYN",
                        PacketDirection::RX => "Received SYN-ACK",
                    },
                    Ipv4Addr::from(event.peer_addr),
                    event.peer_port,
                    Ipv4Addr::from(event.local_addr),
                    event.local_port,
                    event.seq
                );
            }

            guard.clear_ready();
        }

        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
