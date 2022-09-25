use solarxr_protocol::datatypes::hardware_info::HardwareAddress;
use solarxr_protocol::device::{
    DeviceBoundMessage, DeviceBoundMessageHeader, PairingInfo, PairingInfoArgs, PairingResponse,
    PairingResponseArgs, ServerBoundMessage, ServerBoundMessageHeader,
    ServerBoundMessageHeaderArgs,
};
use solarxr_protocol::flatbuffers::{root, FlatBufferBuilder, WIPOffset};
use std::error::Error;
use tokio::net::UdpSocket;

macro_rules! unwrap_or_continue {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                println!("Error: {:?}", e);
                continue;
            }
        }
    };
}

async fn send_fb_message<'f, 'd, T>(
    socket: &UdpSocket,
    addr: &str,
    fbb: &'f mut FlatBufferBuilder<'d>,
    msg: WIPOffset<T>,
) -> Result<(), Box<dyn Error>> {
    fbb.finish(msg, None);

    let finished_data = fbb.finished_data().to_vec();

    fbb.reset();

    socket.send_to(&finished_data, addr).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    println!("Listening on {}", socket.local_addr()?);

    let mut paired_to: Option<String> = None;

    let mut fbb = FlatBufferBuilder::new();

    let hardware_address = HardwareAddress::new(0x0000010203040506);

    let info = PairingInfo::create(
        &mut fbb,
        &PairingInfoArgs {
            hardware_address: Some(&hardware_address),
            paired: false,
        },
    );

    let dev = info.as_union_value();
    let hdr = ServerBoundMessageHeader::create(
        &mut fbb,
        &ServerBoundMessageHeaderArgs {
            req_rep: Some(dev),
            req_rep_type: ServerBoundMessage::PairingInfo,
        },
    );

    fbb.finish(hdr, None);
    let finished_data = fbb.finished_data().to_vec();
    fbb.reset();
    socket
        .send_to(&finished_data, "255.255.255.255:6969")
        .await?;

    let mut buf = vec![0; 1024];

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let buf = buf[..len].to_vec();

        let hdr = unwrap_or_continue!(root::<DeviceBoundMessageHeader>(&buf));

        if hdr.req_rep_type() == DeviceBoundMessage::PairingRequest {
            println!("{} wants to pair", addr);

            match paired_to.as_ref() {
                Some(paired_to) => {
                    println!("Already paired to {}", paired_to);

                    let error = fbb.create_string("Already paired to another device");

                    let response = PairingResponse::create(
                        &mut fbb,
                        &PairingResponseArgs {
                            error: Some(error),
                            hardware_address: Some(&hardware_address),
                        },
                    );

                    let hdr = ServerBoundMessageHeader::create(
                        &mut fbb,
                        &ServerBoundMessageHeaderArgs {
                            req_rep: Some(response.as_union_value()),
                            req_rep_type: ServerBoundMessage::PairingResponse,
                        },
                    );

                    send_fb_message(&socket, &addr.to_string(), &mut fbb, hdr).await?;

                    continue;
                }
                None => {
                    paired_to = Some(addr.to_string());

                    println!("Paired to {}", paired_to.as_ref().unwrap());

                    {
                        let response = PairingResponse::create(
                            &mut fbb,
                            &PairingResponseArgs {
                                error: None,
                                hardware_address: Some(&hardware_address),
                            },
                        );

                        let hdr = ServerBoundMessageHeader::create(
                            &mut fbb,
                            &ServerBoundMessageHeaderArgs {
                                req_rep: Some(response.as_union_value()),
                                req_rep_type: ServerBoundMessage::PairingResponse,
                            },
                        );

                        send_fb_message(&socket, &addr.to_string(), &mut fbb, hdr).await?;
                    }

                    {
                        let info = PairingInfo::create(
                            &mut fbb,
                            &PairingInfoArgs {
                                paired: true,
                                hardware_address: Some(&hardware_address),
                            },
                        );

                        let hdr = ServerBoundMessageHeader::create(
                            &mut fbb,
                            &ServerBoundMessageHeaderArgs {
                                req_rep: Some(info.as_union_value()),
                                req_rep_type: ServerBoundMessage::PairingInfo,
                            },
                        );

                        send_fb_message(&socket, "255.255.255.255:6969", &mut fbb, hdr).await?;
                    }
                }
            }
        }
    }
}
