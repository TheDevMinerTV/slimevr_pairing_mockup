use solarxr_protocol::datatypes::hardware_info::{HardwareAddress, ImuType, McuType};
use solarxr_protocol::device::pairing::{
    DeviceFeatureInfo, DeviceFeatureInfoArgs, DeviceSensorInfo, DeviceSensorInfoArgs,
    ImuFeatureInfo, ImuFeatureInfoArgs, PairingInfo, PairingInfoArgs, PairingResponse,
    PairingResponseArgs, PairingResponseError,
};
use solarxr_protocol::device::{
    DeviceBoundMessage, DeviceBoundMessageHeader, ServerBoundMessage, ServerBoundMessageHeader,
    ServerBoundMessageHeaderArgs,
};
use solarxr_protocol::flatbuffers::{root, FlatBufferBuilder, WIPOffset};
use std::error::Error;
use tokio::net::UdpSocket;

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
    let mac_address = HardwareAddress::new(0x0000010203040506);
    let mcu_type = McuType::Other;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    println!("Listening on {}", socket.local_addr()?);

    let mut paired_to: Option<u32> = None;

    let mut fbb = FlatBufferBuilder::new();

    let info = {
        let display_name = fbb.create_string("Test Device");
        let model = fbb.create_string("Test Model");
        let manufacturer = fbb.create_string("Test Manufacturer");
        let firmware_version = fbb.create_string("0.0.0");

        let mcu_features = DeviceFeatureInfo::create(&mut fbb, &DeviceFeatureInfoArgs {});

        let sensor_features = ImuFeatureInfo::create(
            &mut fbb,
            &ImuFeatureInfoArgs {
                gyroscope_calibration: true,
                accelerometer_calibration: true,
                magnetometer_calibration: true,
            },
        );

        let sensor = DeviceSensorInfo::create(
            &mut fbb,
            &DeviceSensorInfoArgs {
                id: 0,
                type_: ImuType::Other,
                features: Some(sensor_features),
            },
        );

        let sensors = fbb.create_vector(&[sensor]);

        PairingInfo::create(
            &mut fbb,
            &PairingInfoArgs {
                paired_to: 0,
                display_name: Some(display_name),
                model: Some(model),
                manufacturer: Some(manufacturer),
                firmware_version: Some(firmware_version),
                mcu_type,

                features: Some(mcu_features),
                sensors: Some(sensors),
            },
        )
    };

    let dev = info.as_union_value();

    let hdr = ServerBoundMessageHeader::create(
        &mut fbb,
        &ServerBoundMessageHeaderArgs {
            mac_address: Some(&mac_address),
            req_rep: Some(dev),
            req_rep_type: ServerBoundMessage::solarxr_protocol_device_pairing_PairingInfo,
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

        let hdr = unwrap_or_continue!(r:root::<DeviceBoundMessageHeader>(&buf));

        if hdr.req_rep_type() == DeviceBoundMessage::solarxr_protocol_device_pairing_PairingRequest
        {
            let req = unwrap_or_continue!(o:hdr.req_rep_as_solarxr_protocol_device_pairing_pairing_request());

            println!("{} wants to pair", addr);

            match paired_to.as_ref() {
                Some(paired_to) => {
                    println!("Already paired to {}", paired_to);

                    let response = PairingResponse::create(
                        &mut fbb,
                        &PairingResponseArgs {
                            error: PairingResponseError::ALREADY_PAIRED,
                        },
                    );

                    let hdr = ServerBoundMessageHeader::create(
                        &mut fbb,
                        &ServerBoundMessageHeaderArgs {
                            mac_address: Some(&mac_address),
                            req_rep: Some(response.as_union_value()),
                            req_rep_type:
                                ServerBoundMessage::solarxr_protocol_device_pairing_PairingResponse,
                        },
                    );

                    send_fb_message(&socket, &addr.to_string(), &mut fbb, hdr).await?;

                    continue;
                }
                None => {
                    paired_to = Some(req.server_id());

                    println!("Paired to {}", paired_to.as_ref().unwrap());

                    {
                        let response = PairingResponse::create(
                            &mut fbb,
                            &PairingResponseArgs {
                                error: PairingResponseError::NONE,
                            },
                        );

                        let hdr = ServerBoundMessageHeader::create(
                            &mut fbb,
                            &ServerBoundMessageHeaderArgs {
                                mac_address: Some(&mac_address),
                                req_rep: Some(response.as_union_value()),
                                req_rep_type: ServerBoundMessage::solarxr_protocol_device_pairing_PairingResponse
                            },
                        );

                        send_fb_message(&socket, &addr.to_string(), &mut fbb, hdr).await?;
                    }

                    {
                        let info = PairingInfo::create(
                            &mut fbb,
                            &PairingInfoArgs {
                                paired_to: paired_to.unwrap_or(0),
                                display_name: None,
                                model: None,
                                manufacturer: None,
                                firmware_version: None,
                                mcu_type: Default::default(),
                                features: None,
                                sensors: None,
                            },
                        );

                        let hdr = ServerBoundMessageHeader::create(
                            &mut fbb,
                            &ServerBoundMessageHeaderArgs {
                                mac_address: Some(&mac_address),
                                req_rep: Some(info.as_union_value()),
                                req_rep_type:
                                    ServerBoundMessage::solarxr_protocol_device_pairing_PairingInfo,
                            },
                        );

                        send_fb_message(&socket, "255.255.255.255:6969", &mut fbb, hdr).await?;
                    }
                }
            }
        }
    }
}
