use ansi_term::Style;
use dialoguer::theme::ColorfulTheme;
use lazy_static::lazy_static;
use solarxr_protocol::datatypes::hardware_info::McuType;
use solarxr_protocol::device::{
    DeviceBoundMessage, DeviceBoundMessageHeader, DeviceBoundMessageHeaderArgs, PairingRequest,
    PairingRequestArgs, PoweredOnInfo, ServerBoundMessage, ServerBoundMessageHeader,
};
use solarxr_protocol::flatbuffers::{root, FlatBufferBuilder};
use std::collections::HashMap;
use std::error::Error;
use tokio::net::UdpSocket;
use tokio::spawn;
use tokio::sync::broadcast::channel;

macro_rules! unwrap_or_continue {
    (o:$e:expr) => {
        match $e {
            Some(v) => v,
            None => continue,
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

#[derive(Clone, Debug)]
struct DeviceInfo {
    display_name: String,
    ip: String,
    mac: String,
    mcu: McuType,
    manufacturer: String,
    model: String,
    hardware_revision: String,
    firmware_revision: String,
}

#[derive(Clone, Debug)]
enum ListenerMessage {
    PoweredOnInfo(DeviceInfo),
}

#[derive(Clone, Debug)]
enum HandlerMessage {
    Pair(String),
}

lazy_static! {
    static ref BOLD: Style = Style::new().bold();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (listener_tx, mut handler_rx) = channel::<ListenerMessage>(8);
    let (handler_tx, mut listener_rx) = channel::<HandlerMessage>(8);

    spawn(async move {
        let socket = UdpSocket::bind("0.0.0.0:6969").await.unwrap();
        println!("Listening on port 6969");

        let mut fbb = FlatBufferBuilder::new();
        let mut buf = vec![0; 1024];

        while let (len, addr) = socket.recv_from(&mut buf).await.unwrap() {
            let buf = buf[..len].to_vec();

            let hdr = unwrap_or_continue!(r:root::<ServerBoundMessageHeader>(&buf));

            match hdr.req_rep_type() {
                ServerBoundMessage::PoweredOnInfo => {
                    let info = unwrap_or_continue!(o:hdr.req_rep_as_powered_on_info());

                    let hardware_info = info.hardware_info().unwrap();

                    let device_info = DeviceInfo {
                        display_name: hardware_info.display_name().unwrap().to_string(),
                        ip: addr.ip().to_string(),
                        mac: hardware_info
                            .hardware_address()
                            .unwrap()
                            .addr()
                            .to_ne_bytes()[0..6]
                            .iter()
                            .map(|x| format!("{:02X}", x))
                            .collect::<Vec<String>>()
                            .join(":"),
                        mcu: hardware_info.mcu_id(),
                        manufacturer: hardware_info.manufacturer().unwrap().to_string(),
                        model: hardware_info.model().unwrap().to_string(),
                        hardware_revision: hardware_info.hardware_revision().unwrap().to_string(),
                        firmware_revision: hardware_info.firmware_version().unwrap().to_string(),
                    };

                    listener_tx
                        .send(ListenerMessage::PoweredOnInfo(device_info))
                        .unwrap();

                    // println!("Pairing...");
                    //
                    // let request = PairingRequest::create(&mut fbb, &PairingRequestArgs {});
                    //
                    // let hdr = DeviceBoundMessageHeader::create(
                    //     &mut fbb,
                    //     &DeviceBoundMessageHeaderArgs {
                    //         req_rep: Some(request.as_union_value()),
                    //         req_rep_type: DeviceBoundMessage::PairingRequest,
                    //     },
                    // );
                    //
                    // fbb.finish(hdr, None);
                    // let finished_data = fbb.finished_data().to_vec();
                    // socket.send_to(&finished_data, addr).await?;
                }
                ServerBoundMessage::PairingResponse => {
                    let response = unwrap_or_continue!(o:hdr.req_rep_as_pairing_response());

                    match response.error() {
                        Some(error) => {
                            println!("Pairing error: {}", error);
                            // pairable_devices.remove(&addr.to_string());
                        }
                        None => {
                            println!("Pairing successful!");
                            // paired_devices.insert(addr.to_string(), addr.to_string());
                        }
                    }
                }
                ServerBoundMessage::PairingInfo => {
                    let info = unwrap_or_continue!(o:hdr.req_rep_as_pairing_info());

                    if info.paired() {
                        // if paired_devices.contains_key(&addr.to_string()) {
                        //     println!("Device {} got paired with us", addr);
                        // } else {
                        //     println!("Device {} got paired with someone else", addr);
                        //
                        //     pairable_devices.remove(&addr.to_string());
                        // }
                    } else {
                        println!("Device {} got unpaired", addr);

                        // pairable_devices.insert(&addr.to_string(), &addr.to_string());
                    }
                }
                m => {
                    println!("Unknown: {:?}", m);
                }
            }
        }
    });

    spawn(async move {
        let mut pairable_devices: HashMap<String, String> = HashMap::new();
        let mut paired_devices: HashMap<String, String> = HashMap::new();

        while let Ok(m) = handler_rx.recv().await {
            match m {
                ListenerMessage::PoweredOnInfo(req) => {
                    pairable_devices.insert(req.mac.clone(), req.mac.clone());

                    println!("{}", BOLD.paint("==== New tracker found ===="));
                    println!("Display Name: {}", req.display_name);
                    println!("IP: {}", req.ip);
                    println!("MAC: {:?}", req.mac);
                    println!("Manufacturer: {}", req.manufacturer);
                    println!("Model: {}", req.model);
                    println!("MCU: {:?}", req.mcu);
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

                    handler_tx.send(ListenerMessage::Pair(req.ip)).unwrap();
                }
            }
        }
    });

    loop {}
}
