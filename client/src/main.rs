use std::net::SocketAddr;

use clap::{App, Arg};
use futures::stream::StreamExt;
use protocol::{ClientPublicKey, Connection, Message, Publish, RSAConnection, Subscribe};
use tokio::{net::TcpStream, select};
use tokio_util::codec::{FramedRead, LinesCodec};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()?;

    let matches = App::new("RSA - Client")
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .about("Sets a host custom port")
                .default_value("9000")
                .takes_value(true),
        )
        .arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .value_name("HOST")
                .about("Sets custom address")
                .default_value("127.0.0.1")
                .takes_value(true),
        )
        .arg(
            Arg::new("channel")
                .short('c')
                .long("channel")
                .value_name("CHANNEL")
                .about("Set communication channel")
                .default_value("room")
                .takes_value(true),
        )
        .get_matches();

    let address = matches.value_of_t::<String>("address").unwrap();
    let port = matches.value_of_t::<u16>("port").unwrap();
    let channel = matches.value_of_t::<String>("channel").unwrap();

    let stream = TcpStream::connect(SocketAddr::new(address.parse()?, port)).await?;
    let mut conn = Connection::new(stream);

    conn.write_packet(Message::Hello.into()).await?;

    let packet = conn.read_packet().await?;
    let key = bincode::deserialize::<Message>(&packet.message[..])?;

    let server_public_key = if let Message::ServerKeys(server_public_key) = key {
        Some(server_public_key.public_key)
    } else {
        None
    }
    .unwrap();

    let (public_key, private_key) = rsa::generate_key(256);
    let mut rsa_conn = RSAConnection::new(conn, Some(server_public_key), private_key);

    rsa_conn
        .write_packet(
            Message::ClientKeys(ClientPublicKey {
                public_key: public_key,
            })
            .into(),
        )
        .await?;

    let stdin = tokio::io::stdin();
    let mut reader = FramedRead::new(stdin, LinesCodec::new());

    rsa_conn
        .write_packet(
            Message::Subscribe(Subscribe {
                channel: channel.clone(),
            })
            .into(),
        )
        .await?;

    loop {
        select! {
            line = reader.next() => {
                if let Some(line) = line {
                    if let Ok(line) = line {
                        rsa_conn.write_packet(Message::Publish(Publish{
                            channel: channel.clone(),
                            message: line
                        }).into()).await? ;
                    }
                }
            },
            packet = rsa_conn.read_packet() => {
                match packet{
                    Ok(packet) => {
                        let message = bincode::deserialize::<Message>(&packet.message[..])?;
                        match message {
                            Message::Publish(publish) => {
                                info!("{}: {}", publish.channel, publish.message);
                            }
                            _ => {
                                info!("Received message");
                            }
                        }
                    },
                    _ => {
                        info!("Closed connection");
                        return Ok(())
                    }
                }

            }
        }
    }
}
