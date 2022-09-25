use ansi_term::Style;
use dialoguer::theme::ColorfulTheme;
use lazy_static::lazy_static;
use mac_address::MacAddress;
use solarxr_protocol::datatypes::hardware_info::McuType;
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
    display_name: String,
    ip: String,
    port: u16,
    mac: MacAddress,
    mcu: McuType,
    manufacturer: String,
    model: String,
    hardware_revision: String,
    firmware_revision: String,
}

#[derive(Clone, Debug)]
enum ListenerMessage {
    Discovered(DeviceInfo),
    PairFailed(MacAddress, String),
    PairSucceeded(MacAddress),
    PairInfo(MacAddress, bool),
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
                ServerBoundMessage::PoweredOnInfo => {
                    let info = unwrap_or_continue!(o:hdr.req_rep_as_powered_on_info());

                    let hardware_info = info.hardware_info().unwrap();

                    let device_info = DeviceInfo {
                        display_name: hardware_info.display_name().unwrap().to_string(),
                        ip: addr.ip().to_string(),
                        port: addr.port(),
                        mac: parse_mac_address!(hardware_info),
                        mcu: hardware_info.mcu_id(),
                        manufacturer: hardware_info.manufacturer().unwrap().to_string(),
                        model: hardware_info.model().unwrap().to_string(),
                        hardware_revision: hardware_info.hardware_revision().unwrap().to_string(),
                        firmware_revision: hardware_info.firmware_version().unwrap().to_string(),
                    };

                    listener_tx
                        .send(ListenerMessage::Discovered(device_info))
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
                ServerBoundMessage::PairingInfo => {
                    let info = unwrap_or_continue!(o:hdr.req_rep_as_pairing_info());

                    let mac = parse_mac_address!(info);

                    listener_tx
                        .send(ListenerMessage::PairInfo(mac, info.paired()))
                        .unwrap();
                }
                m => {
                    println!("Unknown: {:?}", m);
                }
            }
        }
    });

    spawn(async move {
        let mut devices: HashMap<MacAddress, Device> = HashMap::new();

        while let Ok(m) = handler_rx.recv().await {
            match m {
                ListenerMessage::Discovered(req) => {
                    devices.insert(req.mac, Device::Available(req.clone()));

                    println!("{}", BOLD.paint("==== New tracker found ===="));
                    println!("Display Name: {}", req.display_name);
                    println!("IP: {}", &req.ip);
                    println!("Port: {}", req.port);
                    println!("MAC: {}", req.mac);
                    println!("Manufacturer: {}", req.manufacturer);
                    println!("Model: {}", req.model);
                    println!("MCU: {}", req.mcu.variant_name().unwrap());
                    println!("Hardware revision: {}", req.hardware_revision);
                    println!("Firmware version: {}", req.firmware_revision);
                    println!("{}", BOLD.paint("==========================="));

                    println!("Do you want to pair with this device?");
                    let selection = dialoguer::Select::with_theme(&ColorfulTheme::default())
                        .items(&["Yes", "No"])
                        .default(1)
                        .interact()
                        .unwrap();

                    if selection == 1 {
                        continue;
                    }

                    println!("Pairing...");

                    handler_tx
                        .send(HandlerMessage::Pair(req.ip.clone(), req.port))
                        .unwrap();
                }
                ListenerMessage::PairFailed(mac, error) => {
                    let device = unwrap_or_continue!(o:devices.get(&mac));

                    match device {
                        Device::Available(info) => {
                            println!("Pairing with {}:{} failed: {error}", info.ip, info.port);
                        }
                        _ => {
                            unreachable!()
                        }
                    }
                }
                ListenerMessage::PairSucceeded(mac) => {
                    let device = unwrap_or_continue!(o:devices.get(&mac));

                    match device {
                        Device::Available(info) => {
                            println!("Pairing with {}:{} succeeded", info.ip, info.port);

                            devices.insert(mac, Device::Paired(info.clone()));
                        }
                        _ => {
                            unreachable!()
                        }
                    }
                }
                ListenerMessage::PairInfo(mac, paired) => {
                    let device = unwrap_or_continue!(o:devices.get(&mac));

                    match device {
                        Device::Available(info) => {
                            if paired {
                                println!("{}:{} got paired", info.ip, info.port);

                                devices.insert(mac, Device::Unavailable(info.clone()));
                            }
                        }
                        Device::Paired(info) => {
                            if !paired {
                                println!("{}:{} got unpaired", info.ip, info.port);

                                devices.insert(mac, Device::Available(info.clone()));
                            }
                        }
                        Device::Unavailable(info) => {
                            if !paired {
                                println!("{}:{} got unpaired", info.ip, info.port);

                                devices.insert(mac, Device::Available(info.clone()));
                            }
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
