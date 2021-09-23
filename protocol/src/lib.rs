use std::fmt;

use bytes::{Buf, BytesMut};
use rsa::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ServerPublicKey {
    pub public_key: PublicKey,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct ClientPublicKey {
    pub public_key: PublicKey,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Subscribe {
    pub channel: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Publish {
    pub channel: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Message {
    Hello,
    ServerKeys(ServerPublicKey),
    ClientKeys(ClientPublicKey),
    Subscribe(Subscribe),
    Publish(Publish),
    Close,
}

impl Into<Packet> for Message {
    fn into(self) -> Packet {
        let encoded = bincode::serialize(&self).unwrap();

        Packet {
            length: encoded.len(),
            message: encoded,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Packet {
    pub length: usize,
    pub message: Vec<u8>,
}

pub struct Connection {
    stream: TcpStream,
    buf: BytesMut,
}

#[derive(Debug, Clone)]
struct ConnectionClosedError;

impl fmt::Display for ConnectionClosedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "connection was closed")
    }
}

impl std::error::Error for ConnectionClosedError {}

impl Connection {
    pub fn new(stream: TcpStream) -> Connection {
        Connection {
            stream: stream,
            buf: BytesMut::with_capacity(1024),
        }
    }

    pub async fn read_packet(
        &mut self,
    ) -> Result<Packet, Box<dyn std::error::Error + Send + Sync>> {
        while self.buf.len() < std::mem::size_of::<u64>() {
            let n = self.stream.read_buf(&mut self.buf).await?;

            if n == 0 {
                return Err(Box::new(ConnectionClosedError));
            }
        }

        let len = self.buf.get_u64() as usize;

        while self.buf.len() < len {
            let n = self.stream.read_buf(&mut self.buf).await?;
            if n == 0 {
                return Err(Box::new(ConnectionClosedError));
            }
        }

        let packet: Packet = bincode::deserialize(&self.buf[0..len]).unwrap();
        self.buf = self.buf.split_off(len);

        Ok(packet)
    }

    pub async fn write_packet(
        &mut self,
        packet: Packet,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let encoded: Vec<u8> = bincode::serialize(&packet).unwrap();

        self.stream.write_all(&encoded.len().to_be_bytes()).await?;

        self.stream.write_all(&encoded[..]).await?;
        Ok(())
    }

    pub async fn close(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.write_packet(Message::Close.into()).await
    }
}

pub struct RSAConnection {
    public_key: Option<PublicKey>,
    private_key: PrivateKey,

    conn: Connection,
}

impl RSAConnection {
    pub fn new(
        conn: Connection,
        public_key: Option<PublicKey>,
        private_key: PrivateKey,
    ) -> RSAConnection {
        RSAConnection {
            conn,
            public_key,
            private_key,
        }
    }

    pub fn set_public_key(&mut self, public_key: Option<PublicKey>) {
        self.public_key = public_key
    }

    pub async fn read_packet(
        &mut self,
    ) -> Result<Packet, Box<dyn std::error::Error + Send + Sync>> {
        let packet = self.conn.read_packet().await?;
        let decoded = self.private_key.decrypt(&packet.message[..]);

        Ok(Packet {
            length: decoded.len(),
            message: decoded,
        })
    }

    pub async fn write_packet(
        &mut self,
        packet: Packet,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(public_key) = &self.public_key {
            let data = public_key.encrypt(&packet.message[..]);

            self.conn
                .write_packet(Packet {
                    length: data.len(),
                    message: data,
                })
                .await
        } else {
            self.conn.write_packet(packet).await
        }
    }

    pub async fn close(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.write_packet(Message::Close.into()).await
    }
}
