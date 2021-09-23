use std::{
    collections::{HashMap, HashSet},
    io::{Error, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use clap::{App, Arg};
use rsa::{generate_key, PrivateKey, PublicKey};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
    sync::Mutex,
};
use tracing::{debug, error, info};

use protocol::{Connection, Message, Publish, RSAConnection, ServerPublicKey};

type ChannelStorage = Arc<
    Mutex<
        HashMap<
            String,
            (
                tokio::sync::broadcast::Sender<(String, SocketAddr)>,
                tokio::sync::broadcast::Receiver<(String, SocketAddr)>,
            ),
        >,
    >,
>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()?;

    let matches = App::new("RSA - Server")
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
        .get_matches();

    info!("Starting RSA Server");

    info!("Generating RSA Key");
    let (public_key, private_key) = generate_key(256);
    let (public_key, private_key) = (Arc::new(public_key), Arc::new(private_key));
    info!("Successfully Generated Key");

    let address = matches.value_of_t::<String>("address").unwrap();
    let port = matches.value_of_t::<u64>("port").unwrap();

    let host = format!("{}:{}", address, port);
    let listener = TcpListener::bind(host.clone()).await?;

    info!("Listening at {}", host);

    let channels: ChannelStorage = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        info!("Receiving new connection from {}", addr);

        let public_key_clone = public_key.clone();
        let private_key_clone = private_key.clone();

        let channels_clone = channels.clone();
        tokio::spawn(async move {
            let result = handle_connection(
                socket,
                addr,
                (public_key_clone, private_key_clone),
                channels_clone,
            )
            .await;
            if let Err(e) = result {
                error!("Connection closed with error {}", e);
            } else {
                info!("Connection closed");
            }
        });
    }
}

async fn handle_connection(
    socket: TcpStream,
    addr: SocketAddr,
    key_pair: (Arc<PublicKey>, Arc<PrivateKey>),
    channels: ChannelStorage,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = Connection::new(socket);

    let mut conn = handshake(conn, key_pair).await?;
    let mut connected_channels: HashSet<String> = HashSet::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String, SocketAddr)>(16);

    loop {
        select! {
            packet = conn.read_packet() => {
                let message = bincode::deserialize::<Message>(&packet?.message)?;
                match message {
                    Message::Close => return Ok(()),
                    Message::Subscribe(subscribe) => {
                        connected_channels.insert(subscribe.channel.clone());
                        let mut guard = channels.lock().await;
                        let channel = guard.get(&subscribe.channel);

                        if let Some(channel) = channel {
                            let mut receiver = channel.0.subscribe();
                            let tx_clone = tx.clone();
                            tokio::spawn(async move {
                                loop {
                                    let msg = receiver.recv().await;

                                    if let Ok(msg) = msg {
                                        if msg.1 != addr {
                                            let _ = tx_clone.send((subscribe.channel.clone(), msg.0, msg.1)).await;
                                        }
                                    }
                                }
                            });
                        } else {
                            let channel = tokio::sync::broadcast::channel::<(String, SocketAddr)>(32);
                            let mut receiver = channel.0.subscribe();
                            guard.insert(subscribe.channel.clone(), channel);

                            let tx_clone = tx.clone();
                            tokio::spawn(async move {
                                loop {
                                    let msg = receiver.recv().await;

                                    if let Ok(msg) = msg {
                                        if msg.1 != addr {
                                            let _ = tx_clone.send((subscribe.channel.clone(), msg.0, msg.1)).await;
                                        }
                                    }
                                }
                            });
                        }
                    }
                    Message::Publish(publish) => {
                        info!(
                            "received message {} to channel {}",
                            publish.message, publish.channel
                        );

                        let guard = channels.lock().await;
                        let channel = guard.get(&publish.channel);

                        if let Some(channel) = channel {
                            channel.0.send((publish.message, addr))?;
                        }
                    }
                    _ => {}
                }
            },
            msg = rx.recv() => {
                if let Some(msg) = msg {
                    conn.write_packet(Message::Publish(Publish{
                        channel: msg.0,
                        message: msg.1
                    }).into()).await?;
                }
            }
        }
    }
}

async fn handshake(
    mut conn: Connection,
    key_pair: (Arc<PublicKey>, Arc<PrivateKey>),
) -> Result<RSAConnection, Box<dyn std::error::Error + Send + Sync>> {
    info!("Waiting for hello packet");
    let hello_packet = conn.read_packet().await?;
    let hello = bincode::deserialize::<Message>(&hello_packet.message)?;

    if hello != Message::Hello {
        return Err(Box::new(Error::new(
            ErrorKind::InvalidData,
            "client didn't sent hello message",
        )));
    }

    debug!("Received ACK");

    conn.write_packet(
        Message::ServerKeys(ServerPublicKey {
            public_key: (*key_pair.0).clone(),
        })
        .into(),
    )
    .await?;

    debug!("Public Key Sent");

    let mut rsa_conn = RSAConnection::new(conn, None, (*key_pair.1).clone());

    debug!("Waiting client keys");
    let client_keys_packet = rsa_conn.read_packet().await?;
    let client_keys = bincode::deserialize::<Message>(&client_keys_packet.message)?;

    debug!("Client keys received");

    if let Message::ClientKeys(client_keys) = client_keys {
        dbg!(&client_keys.public_key);
        rsa_conn.set_public_key(Some(client_keys.public_key));
    };

    Ok(rsa_conn)
}
