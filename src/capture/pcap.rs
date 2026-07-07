use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::SocketAddr;

use futures::Stream;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::instrument;

use super::*;

pub struct PcapBackend;

#[derive(Debug, Clone)]
pub struct PcapDevice {
    addr: SocketAddr,
    id: u64,
}

pub struct PcapCapture {
    addr: SocketAddr,
    id: u64,
}

impl CaptureBackend for PcapBackend {
    type Device = PcapDevice;

    fn list_devices(&self) -> Result<Vec<Self::Device>> {
        let addr: SocketAddr = "0.0.0.0:1234".parse().unwrap();

        let mut hasher = DefaultHasher::new();
        "pcap-over-ip".hash(&mut hasher);

        Ok(vec![PcapDevice {
            addr,
            id: hasher.finish(),
        }])
    }
}

impl CaptureDevice for PcapDevice {
    type Capture = PcapCapture;

    fn name(&self) -> &str {
        "pcap-over-ip"
    }

    fn create_capture(&self) -> Result<Self::Capture> {
        Ok(PcapCapture {
            addr: self.addr,
            id: self.id,
        })
    }
}

impl PacketCapture for PcapCapture {
    #[instrument(skip_all)]
    fn capture_packets(self) -> Result<impl Stream<Item = Result<Packet>> + Unpin + Send> {
        let addr = self.addr;
        let source_id = self.id;
 
        Ok(Box::pin(async_stream::stream! {
            let mut has_captured = false;
 
            // NOTE: intentionally NOT wrapped in a nested `async {}` block.
            // async_stream's `yield` rewriting does not recurse into nested
            // async blocks/closures, so any `yield` inside one is left as
            // literal (unstable) generator syntax and fails to compile.
            // Errors are propagated by yielding an `Err(..)` and `return`ing
            // instead of using `?`.
 
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    yield Err(CaptureError::CaptureError {
                        has_captured,
                        error: Box::new(e),
                    });
                    return;
                }
            };
 
            tracing::info!(%addr, "waiting for PCAPdroid connection");
 
            'accept: loop {
                let (mut stream, peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(%e, "accept failed, retrying");
                        continue 'accept;
                    }
                };
 
                tracing::info!(%peer, "PCAPdroid connected");
 
                // PCAP global header
                let mut global = [0u8; 24];
                if let Err(e) = stream.read_exact(&mut global).await {
                    yield Err(CaptureError::CaptureError {
                        has_captured,
                        error: Box::new(e),
                    });
                    return;
                }
 
                let magic = u32::from_le_bytes(global[0..4].try_into().unwrap());
 
                let little_endian = match magic {
                    0xa1b2c3d4 | 0xa1b23c4d => true,
                    0xd4c3b2a1 | 0x4d3cb2a1 => false,
                    _ => {
                        yield Err(CaptureError::CaptureError {
                            has_captured,
                            error: "invalid pcap magic".into(),
                        });
                        return;
                    }
                };
 
                let linktype = ::pcap::Linktype(
                    if little_endian {
                        u32::from_le_bytes(global[20..24].try_into().unwrap())
                    } else {
                        u32::from_be_bytes(global[20..24].try_into().unwrap())
                    } as i32,
                );
 
                'packets: loop {
                    let mut packet_header = [0u8; 16];
 
                    match stream.read_exact(&mut packet_header).await {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            break 'packets;
                        }
                        Err(e) => {
                            yield Err(CaptureError::CaptureError {
                                has_captured,
                                error: Box::new(e),
                            });
                            return;
                        }
                    }
 
                    let captured_len = if little_endian {
                        u32::from_le_bytes(packet_header[8..12].try_into().unwrap())
                    } else {
                        u32::from_be_bytes(packet_header[8..12].try_into().unwrap())
                    };
 
                    let mut payload = vec![0u8; captured_len as usize];
                    match stream.read_exact(&mut payload).await {
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            break 'packets;
                        }
                        Err(e) => {
                            yield Err(CaptureError::CaptureError {
                                has_captured,
                                error: Box::new(e),
                            });
                            return;
                        }
                    }
 
                    let payload = match normalize_offline_pcap_payload(linktype, &payload) {
                        Ok(payload) => payload,
                        Err(e) => {
                            tracing::debug!(%e, "dropping packet during normalization");
                            continue 'packets;
                        }
                    };
 
                    if !is_udp_port_packet(&payload) {
                        continue 'packets;
                    }
 
                    has_captured = true;
 
                    yield Ok(Packet {
                        source_id,
                        data: payload,
                    });
                }
            }
        }))
    }
}

fn is_udp_port_packet(frame: &[u8]) -> bool {
    if frame.len() < 14 {
        return false;
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let ip_offset = 14;

    match ethertype {
        0x0800 => {
            if frame.len() < ip_offset + 20 {
                return false;
            }

            if frame[ip_offset + 9] != 17 {
                return false;
            }

            let header_len = (frame[ip_offset] & 0x0f) as usize * 4;
            udp_ports_match(frame, ip_offset + header_len)
        }

        0x86dd => {
            if frame.len() < ip_offset + 40 {
                return false;
            }

            if frame[ip_offset + 6] != 17 {
                return false;
            }

            udp_ports_match(frame, ip_offset + 40)
        }

        _ => false,
    }
}

fn udp_ports_match(frame: &[u8], offset: usize) -> bool {
    if frame.len() < offset + 4 {
        return false;
    }

    let src = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    let dst = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);

    (23301..=23302).contains(&src)
        || (23301..=23302).contains(&dst)
}
