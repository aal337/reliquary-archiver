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

            let result: std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> =
                async {
                    let listener = tokio::net::TcpListener::bind(addr).await?;

                    tracing::info!(%addr, "waiting for PCAPdroid connection");

                    loop {
                        let (mut stream, peer) = match listener.accept().await {
                            Ok(pair) => pair,
                            Err(e) => tracing::warn!(%e, "accept failed, retrying");
                            continue;
                        };

                        tracing::info!(%peer, "PCAPdroid connected");

                        // PCAP global header
                        let mut global = [0u8; 24];
                        stream.read_exact(&mut global).await?;

                        let magic = u32::from_le_bytes(global[0..4].try_into()?);

                        let little_endian = match magic {
                            0xa1b2c3d4 | 0xa1b23c4d => true,
                            0xd4c3b2a1 | 0x4d3cb2a1 => false,
                            _ => return Err("invalid pcap magic".into()),
                        };

                        let linktype = ::pcap::Linktype(
                            if little_endian {
                                u32::from_le_bytes(global[20..24].try_into()?)
                            } else {
                                u32::from_be_bytes(global[20..24].try_into()?)
                            } as i32
                        );

                        loop {
                            let mut packet_header = [0u8; 16];

                            match stream.read_exact(&mut packet_header).await {
                                Ok(_) => {}
                                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                                    break;
                                }
                                Err(e) => return Err(e.into()),
                            }

                            let captured_len = if little_endian {
                                u32::from_le_bytes(packet_header[8..12].try_into()?)
                            } else {
                                u32::from_be_bytes(packet_header[8..12].try_into()?)
                            };

                            let mut payload = vec![0u8; captured_len as usize];
                            match stream.read_exact(&mut payload).await {
                                Ok(_) => {}
                                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                                    break;
                                }
                                Err(e) => return Err(e.into()),
                            }

                            let payload = match normalize_offline_pcap_payload(
                                linktype,
                                &payload,
                            ) {
                                Ok(payload) => payload,
                                Err(e) => {
                                    debug!(%e, "dropping packet during normalization");
                                    continue;
                                }
                            };

                            if !is_udp_port_packet(&payload) {
                                continue;
                            }

                            has_captured = true;

                            yield Ok(Packet {
                                source_id,
                                data: payload,
                            });
                        }

                        Ok(())
                    }
                }
                .await;

            if let Err(e) = result {
                yield Err(CaptureError::CaptureError {
                    has_captured,
                    error: e,
                });
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
