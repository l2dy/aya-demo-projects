use std::fs;
use std::path::Path;

use anyhow::Context;
use aya::maps::{Map, MapData, RingBuf};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, BpfLoader, Btf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use ringbufpin_common::TcpHandshakeEvent;
use tokio::io::unix::AsyncFd;
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

    // Exit if bpffs is not mounted.
    fs::metadata("/sys/fs/bpf")?;

    let pin_path = "/sys/fs/bpf/ringbufpin";
    let map_pin_path = "/sys/fs/bpf/ringbufpin/TCPHSEVENTS";
    if fs::metadata(map_pin_path).is_ok() {
        // map exists, purge it
        fs::remove_file(map_pin_path)?;
    } else {
        // ensure parent directory exists
        fs::create_dir_all(pin_path)?;
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .map_pin_path(pin_path)
        .load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/ringbufpin"
        ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .map_pin_path(pin_path)
        .load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/ringbufpin"
        ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("ringbufpin").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
           .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let map_pin_path = Path::new("/sys/fs/bpf/ringbufpin/TCPHSEVENTS");
    let map_data = MapData::from_pin(map_pin_path)?;
    let map = Map::RingBuf(map_data);
    let ring_buf = RingBuf::try_from(map)?;
    let mut async_ring_buf = AsyncFd::new(ring_buf)?;

    task::spawn(async move {
        loop {
            let mut guard = async_ring_buf.readable_mut().await?;
            let entry = guard.get_inner_mut();
            while let Some(event) = entry.next() {
                let event_ptr = event.as_ptr() as *const TcpHandshakeEvent;

                let event = unsafe { event_ptr.read_unaligned() };

                debug!(
                    "Received SYN-ACK, peer {}, local {}",
                    event.peer_port, event.local_port
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
