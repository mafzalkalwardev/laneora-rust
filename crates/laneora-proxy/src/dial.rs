use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::net::TcpStream;

use crate::{dns_query, first_a_record, parse_host_port};

/// Dial `host:port`. On Linux, when `iface` is set, the socket and the DNS
/// query are bound to that interface (`SO_BINDTODEVICE`).
pub async fn dial_via(host_port: &str, iface: &str) -> io::Result<TcpStream> {
    let (host, port) = parse_host_port(host_port)?;
    let ip = if let Ok(ip) = host.parse::<IpAddr>() {
        ip
    } else {
        IpAddr::V4(resolve_a(&host, iface).await?)
    };
    connect_bound(SocketAddr::new(ip, port), iface).await
}

pub async fn connect_bound(addr: SocketAddr, iface: &str) -> io::Result<TcpStream> {
    let domain = match addr {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    bind_device(&socket, iface)?;
    let std_stream: std::net::TcpStream = socket.into();
    let tokio_socket = tokio::net::TcpSocket::from_std_stream(std_stream);
    tokio_socket.connect(addr).await
}

async fn resolve_a(host: &str, iface: &str) -> io::Result<Ipv4Addr> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_nonblocking(true)?;
    bind_device(&socket, iface)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let udp = tokio::net::UdpSocket::from_std(std_socket)?;
    udp.connect("1.1.1.1:53").await?;
    let query = dns_query(0x4C41, host);
    udp.send(&query).await?;
    let mut buf = [0u8; 1500];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), udp.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns timeout"))??;
    first_a_record(&buf[..read]).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no A record"))
}

fn bind_device(socket: &socket2::Socket, iface: &str) -> io::Result<()> {
    if iface.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        socket.bind_device(Some(iface.as_bytes()))?;
        return Ok(());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SO_BINDTODEVICE is only available on Linux",
        ))
    }
}
