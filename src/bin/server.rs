use ansi_term::Style;
use dialoguer::theme::ColorfulTheme;
use lazy_static::lazy_static;
use mac_address::MacAddress;
use rand::Rng;
use solarxr_protocol::datatypes::hardware_info::{ImuType, McuType};
use solarxr_protocol::device::pairing::{
    DiscoverRequest, DiscoverRequestArgs, PairingRequestArgs, PairingResponseError,
};
use solarxr_protocol::device::{
    pairing::PairingRequest, DeviceBoundMessage, DeviceBoundMessageHeader,
    DeviceBoundMessageHeaderArgs, ServerBoundMessage, ServerBoundMessageHeader,
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
            $hwi.mac_address().addr().to_le_bytes()[0..6]
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
struct DeviceFeatures {}

#[derive(Clone, Debug)]
struct DeviceSensorFeatures {}

#[derive(Clone, Debug)]
struct DeviceSensorInfo {
    type_: ImuType,
    features: DeviceSensorFeatures,
}

#[derive(Clone, Debug)]
struct DeviceInfo {
    ip: String,
    port: u16,
    mac: MacAddress,

    display_name: String,
    model: String,
    manufacturer: String,
    firmware_version: String,
    mcu_type: McuType,

    features: DeviceFeatures,
    sensors: HashMap<u8, DeviceSensorInfo>,
}

#[derive(Clone, Debug)]
enum ListenerMessage {
    PairInfo {
        mac: MacAddress,
        device_info: DeviceInfo,
        paired_to: Option<u32>,
    },
    PairFailed(MacAddress, String),
    PairSucceeded(MacAddress),
}

#[derive(Clone, Debug)]
enum HandlerMessage {
    Pair(String, u16),
    Discover,
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
    let mut rng = rand::thread_rng();
    let server_id = rng.gen::<u32>();

    let (listener_tx, mut handler_rx) = channel::<ListenerMessage>(8);
    let (handler_tx, mut listener_rx) = channel::<HandlerMessage>(8);
    let handler_tx_2 = handler_tx.clone();

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
            let mac = parse_mac_address!(hdr);

            match hdr.req_rep_type() {
                ServerBoundMessage::solarxr_protocol_device_pairing_PairingInfo => {
                    let info = unwrap_or_continue!(o:hdr.req_rep_as_solarxr_protocol_device_pairing_pairing_info());

                    let mut sensors = HashMap::new();
                    for sensor in info.sensors() {
                        match sensors.get(&sensor.id()) {
                            Some(_) => continue,
                            None => sensors.insert(
                                sensor.id(),
                                DeviceSensorInfo {
                                    type_: sensor.type_(),
                                    features: DeviceSensorFeatures {},
                                },
                            ),
                        };
                    }

                    let device_info = DeviceInfo {
                        ip: addr.ip().to_string(),
                        port: addr.port(),
                        mac,
                        display_name: info.display_name().to_string(),
                        model: info.model().to_string(),
                        manufacturer: info.manufacturer().to_string(),
                        firmware_version: info.firmware_version().to_string(),
                        mcu_type: info.mcu_type(),
                        features: DeviceFeatures {},
                        sensors,
                    };

                    listener_tx
                        .send(ListenerMessage::PairInfo {
                            mac,
                            device_info,
                            paired_to: if info.paired_to() == 0 {
                                None
                            } else {
                                Some(info.paired_to())
                            },
                        })
                        .unwrap();
                }
                ServerBoundMessage::solarxr_protocol_device_pairing_PairingResponse => {
                    let response = unwrap_or_continue!(o:hdr.req_rep_as_solarxr_protocol_device_pairing_pairing_response());

                    match response.error() {
                        PairingResponseError::NONE => {
                            listener_tx
                                .send(ListenerMessage::PairSucceeded(mac))
                                .unwrap();
                        }
                        PairingResponseError::ALREADY_PAIRED => {
                            listener_tx
                                .send(ListenerMessage::PairFailed(
                                    mac,
                                    "Already paired to another device".to_string(),
                                ))
                                .unwrap();
                        }
                        _ => {}
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
                ListenerMessage::PairInfo {
                    mac,
                    device_info,
                    paired_to,
                } => match devices.get(&mac) {
                    None | Some(Device::Available(_)) | Some(Device::Pairing(_))
                        if paired_to.is_some() =>
                    {
                        println!(
                            "{}:{} got paired with another device",
                            device_info.ip, device_info.port
                        );

                        devices.insert(mac, Device::Unavailable(device_info.clone()));
                    }

                    /*
                       The match guard condition will apply to all the patterns.
                       ref: https://doc.rust-lang.org/book/ch18-03-pattern-syntax.html#extra-conditionals-with-match-guards
                    */
                    None | Some(Device::Unavailable(_)) | Some(Device::Paired(_))
                        if paired_to.is_some() =>
                    {
                        devices.insert(mac, Device::Available(device_info.clone()));

                        if ignored_trackers.contains_key(&device_info.mac) {
                            continue;
                        }

                        println!("{}", BOLD.paint("==== New tracker found ===="));
                        println!("IP: {}", &device_info.ip);
                        println!("Port: {}", device_info.port);
                        println!("MAC: {}", device_info.mac);
                        println!("Display name: {}", device_info.display_name);
                        println!("Model: {}", device_info.model);
                        println!("Manufacturer: {}", device_info.manufacturer);
                        println!("Firmware version: {}", device_info.firmware_version);
                        println!("MCU type: {:?}", device_info.mcu_type);
                        println!("Features: {:?}", device_info.features);
                        println!("Sensors:");
                        for (id, sensor) in device_info.sensors.iter() {
                            println!("  - ID: {}", id);
                            println!("    Type: {:?}", sensor.type_);
                            println!("    Features: {:?}", sensor.features);
                        }
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

                            ignored_trackers.insert(device_info.mac, ());

                            continue;
                        }

                        println!("Pairing...");

                        devices.insert(mac, Device::Pairing(device_info.clone()));

                        handler_tx
                            .send(HandlerMessage::Pair(
                                device_info.ip.clone(),
                                device_info.port,
                            ))
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
                    let request =
                        PairingRequest::create(&mut fbb, &PairingRequestArgs { server_id });

                    let hdr = DeviceBoundMessageHeader::create(
                        &mut fbb,
                        &DeviceBoundMessageHeaderArgs {
                            req_rep: Some(request.as_union_value()),
                            req_rep_type:
                                DeviceBoundMessage::solarxr_protocol_device_pairing_PairingRequest,
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
                HandlerMessage::Discover => {
                    let request = DiscoverRequest::create(&mut fbb, &DiscoverRequestArgs {});

                    let hdr = DeviceBoundMessageHeader::create(
                        &mut fbb,
                        &DeviceBoundMessageHeaderArgs {
                            req_rep: Some(request.as_union_value()),
                            req_rep_type:
                                DeviceBoundMessage::solarxr_protocol_device_pairing_DiscoverRequest,
                        },
                    );

                    fbb.finish(hdr, None);
                    let finished_data = fbb.finished_data().to_vec();
                    fbb.reset();
                    socket
                        .send_to(&finished_data, "172.31.179.23:7000")
                        .await
                        .unwrap();
                }
            }
        }
    });

    handler_tx_2.send(HandlerMessage::Discover)?;

    loop {
        sleep(Duration::from_secs(1));
    }
}
