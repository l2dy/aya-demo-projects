#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub enum PacketDirection {
    TX,
    RX,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TcpHandshakeEvent {
    pub peer_addr: u32,
    pub peer_port: u16,
    pub local_addr: u32,
    pub local_port: u16,
    pub seq: u32,
    pub direction: PacketDirection,
}
