use ansi_term::Style;
use dialoguer::theme::ColorfulTheme;
use lazy_static::lazy_static;
use mac_address::MacAddress;
use solarxr_protocol::device::{
    DeviceBoundMessage, DeviceBoundMessageHeader, DeviceBoundMessageHeaderArgs, PairingRequest,
    PairingRequestArgs, ServerBoundMessage, ServerBoundMessageHeader,
};
use solarxr_protocol::flatbuffers::{root, FlatBufferBuilder};
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::spawn;
use tokio::sync::broadcast::channel;

macro_rules! unwrap_or_continue {
    (o:$e:expr) => {
        match $e {
            Some(v) => v,
            None => {
                println!("Couldn't unwrap for some reason");
                continue;
            }
        }
    };
    (r:$e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                println!("Error: {:?}", e);
                continue;
            }
        }
    };
}

macro_rules! parse_mac_address {
    ($hwi:expr) => {
        MacAddress::from_str(
            $hwi.hardware_address().unwrap().addr().to_le_bytes()[0..6]
                .iter()
                .map(|x| format!("{:02X}", x))
                .collect::<Vec<String>>()
                .join(":")
                .as_str(),
        )
        .unwrap()
    };
}

#[derive(Clone, Debug)]
struct DeviceInfo {
    ip: String,
    port: u16,
    mac: MacAddress,
}

#[derive(Clone, Debug)]
enum ListenerMessage {
    PairInfo(MacAddress, DeviceInfo, bool),
    PairFailed(MacAddress, String),
    PairSucceeded(MacAddress),
}

#[derive(Clone, Debug)]
enum HandlerMessage {
    Pair(String, u16),
}

lazy_static! {
    static ref BOLD: Style = Style::new().bold();
}

enum Device {
    Available(DeviceInfo),
    Unavailable(DeviceInfo),
    Pairing(DeviceInfo),
    Paired(DeviceInfo),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (listener_tx, mut handler_rx) = channel::<ListenerMessage>(8);
    let (handler_tx, mut listener_rx) = channel::<HandlerMessage>(8);

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:6969").await.unwrap());
    println!("Listening on port 6969");

    let receiver_socket = socket.clone();
    spawn(async move {
        let socket = receiver_socket;
        let mut buf = vec![0; 1024];

        loop {
            let (len, addr) = socket.recv_from(&mut buf).await.unwrap();

            let buf = buf[..len].to_vec();

            let hdr = unwrap_or_continue!(r:root::<ServerBoundMessageHeader>(&buf));

            match hdr.req_rep_type() {
                ServerBoundMessage::PairingInfo => {
                    let info = unwrap_or_continue!(o:hdr.req_rep_as_pairing_info());

                    let mac = parse_mac_address!(info);

                    let device_info = DeviceInfo {
                        ip: addr.ip().to_string(),
                        port: addr.port(),
                        mac,
                    };

                    listener_tx
                        .send(ListenerMessage::PairInfo(mac, device_info, info.paired()))
                        .unwrap();
                }
                ServerBoundMessage::PairingResponse => {
                    let response = unwrap_or_continue!(o:hdr.req_rep_as_pairing_response());
                    let mac = parse_mac_address!(response);

                    match response.error() {
                        Some(error) => {
                            listener_tx
                                .send(ListenerMessage::PairFailed(mac, error.to_string()))
                                .unwrap();
                        }
                        None => {
                            listener_tx
                                .send(ListenerMessage::PairSucceeded(mac))
                                .unwrap();
                        }
                    }
                }
                m => {
                    println!("Unknown: {:?}", m);
                }
            }
        }
    });

    spawn(async move {
        let mut devices: HashMap<MacAddress, Device> = HashMap::new();
        let mut ignored_trackers: HashMap<MacAddress, ()> = HashMap::new();

        while let Ok(m) = handler_rx.recv().await {
            match m {
                ListenerMessage::PairInfo(mac, info, paired) => match devices.get(&mac) {
                    Some(Device::Available(info)) | Some(Device::Pairing(info)) if paired => {
                        println!("{}:{} got paired with another device", info.ip, info.port);

                        devices.insert(mac, Device::Unavailable(info.clone()));
                    }

                    /*
                       The match guard condition will apply to all the patterns.
                       ref: https://doc.rust-lang.org/book/ch18-03-pattern-syntax.html#extra-conditionals-with-match-guards
                    */
                    None | Some(Device::Unavailable(_)) | Some(Device::Paired(_)) if !paired => {
                        devices.insert(mac, Device::Available(info.clone()));

                        if ignored_trackers.contains_key(&info.mac) {
                            continue;
                        }

                        println!("{}", BOLD.paint("==== New tracker found ===="));
                        println!("IP: {}", &info.ip);
                        println!("Port: {}", info.port);
                        println!("MAC: {}", info.mac);
                        println!("{}", BOLD.paint("==========================="));

                        // TODO: Find a way to cancel this prompt when
                        //       the device was already paired, probably have
                        //       to use another green thread for this though
                        println!("Do you want to pair with this device?");
                        let selection = dialoguer::Select::with_theme(&ColorfulTheme::default())
                            .items(&["Yes", "No"])
                            .default(1)
                            .interact()
                            .unwrap();

                        if selection == 1 {
                            println!("Ignoring this device...");

                            ignored_trackers.insert(info.mac, ());

                            continue;
                        }

                        println!("Pairing...");

                        devices.insert(mac, Device::Pairing(info.clone()));

                        handler_tx
                            .send(HandlerMessage::Pair(info.ip.clone(), info.port))
                            .unwrap();
                    }
                    _ => {}
                },
                ListenerMessage::PairFailed(mac, error) => {
                    let device = unwrap_or_continue!(o:devices.get(&mac));

                    match device {
                        Device::Pairing(info) => {
                            println!("Pairing with {}:{} failed: {error}", info.ip, info.port);
                        }
                        _ => {
                            unreachable!("device should be pairing when we receive this message");
                        }
                    }
                }
                ListenerMessage::PairSucceeded(mac) => {
                    let device = unwrap_or_continue!(o:devices.get(&mac));

                    match device {
                        Device::Pairing(info) => {
                            println!("Pairing with {}:{} succeeded", info.ip, info.port);

                            devices.insert(mac, Device::Paired(info.clone()));
                        }
                        _ => {
                            unreachable!("device should be pairing when we receive this message");
                        }
                    }
                }
            }
        }
    });

    let handler_socket = socket;
    spawn(async move {
        let socket = handler_socket;
        let mut fbb = FlatBufferBuilder::new();

        while let Ok(m) = listener_rx.recv().await {
            match m {
                HandlerMessage::Pair(ip, port) => {
                    let request = PairingRequest::create(&mut fbb, &PairingRequestArgs {});

                    let hdr = DeviceBoundMessageHeader::create(
                        &mut fbb,
                        &DeviceBoundMessageHeaderArgs {
                            req_rep: Some(request.as_union_value()),
                            req_rep_type: DeviceBoundMessage::PairingRequest,
                        },
                    );

                    fbb.finish(hdr, None);
                    let finished_data = fbb.finished_data().to_vec();
                    fbb.reset();
                    socket
                        .send_to(&finished_data, SocketAddr::new(ip.parse().unwrap(), port))
                        .await
                        .unwrap();
                }
            }
        }
    });

    loop {
        sleep(Duration::from_secs(1));
    }
}
