//! HTTP and HTTPS CONNECT proxy. Outbound dials can be locked to one interface.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

use base64::{engine::general_purpose::STANDARD, Engine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub mod dial;
pub mod watchdog;

pub type DialFut = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;

pub fn basic_token(user: &str, pass: &str) -> String {
    STANDARD.encode(format!("{user}:{pass}"))
}

pub fn ip_change_message(previous: &mut String, ip: &str, city: &str, country: &str) -> Option<String> {
    if previous == ip {
        return None;
    }
    let message = format!("Laneora proxy IP active: {ip} ({city}, {country})");
    *previous = ip.to_string();
    Some(message)
}

pub fn tunnel_down_message(error: &str) -> String {
    format!("ALERT: Surfshark wg0 tunnel down. Kill-switch is blocking DAT traffic: {error}")
}

/// Read one proxy client and tunnel it through `dial`.
pub async fn handle_proxy<F>(mut client: TcpStream, expected_b64: &str, mut dial: F) -> io::Result<()>
where
    F: FnMut(String) -> DialFut,
{
    let header_buf = read_headers(&mut client).await?;
    let header_end = header_buf
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "headers did not end"))?;
    let head = String::from_utf8_lossy(&header_buf[..header_end]).to_string();
    let leftover = header_buf[header_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let request = lines.next().unwrap_or("");
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method.is_empty() || target.is_empty() {
        return Ok(());
    }

    let mut authorized = false;
    let mut forward_headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some(value) = strip_prefix_ignore_ascii_case(line, "Proxy-Authorization: Basic ") {
            if ct_eq(value.trim(), expected_b64) {
                authorized = true;
            }
        } else if !line.to_ascii_lowercase().starts_with("proxy-") {
            forward_headers.push(line.to_string());
        }
    }
    if !authorized {
        let body = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Laneora\"\r\nContent-Length: 0\r\n\r\n";
        client.write_all(body.as_bytes()).await?;
        return Ok(());
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let mut upstream = dial(target.to_string())
            .await
            .map_err(|err| io::Error::new(err.kind(), format!("dial {target}: {err}")))?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if !leftover.is_empty() {
            upstream.write_all(&leftover).await?;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        return Ok(());
    }

    let stripped = target.strip_prefix("http://").unwrap_or(target);
    let (host_port, path) = match stripped.find('/') {
        Some(index) => (&stripped[..index], &stripped[index..]),
        None => (stripped, "/"),
    };
    let connect_addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };
    let mut upstream = dial(connect_addr.clone())
        .await
        .map_err(|err| io::Error::new(err.kind(), format!("dial {connect_addr}: {err}")))?;
    let mut request = format!("{method} {path} HTTP/1.1\r\n");
    for header in forward_headers {
        request.push_str(&header);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    upstream.write_all(request.as_bytes()).await?;
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn read_headers(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let read = stream.read(&mut tmp).await?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..read]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") || buf.len() > 64 * 1024 {
            break;
        }
    }
    if buf.is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty request"));
    }
    Ok(buf)
}

fn strip_prefix_ignore_ascii_case<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    if line.len() < prefix.len() {
        return None;
    }
    if line[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&line[prefix.len()..])
    } else {
        None
    }
}

fn ct_eq(left: &str, right: &str) -> bool {
    let a = left.as_bytes();
    let b = right.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn parse_host_port(target: &str) -> io::Result<(String, u16)> {
    let target = target.trim();
    if let Some(addr) = target.parse::<SocketAddr>().ok() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let (host, port) = target.rsplit_once(':').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "missing port")
    })?;
    let port = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad port"))?;
    if host.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "missing host"));
    }
    Ok((host.to_string(), port))
}

/// Build a DNS A query. The caller sends it through a socket bound to wg0.
pub fn dns_query(id: u16, host: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in host.split('.') {
        let bytes = label.as_bytes();
        packet.push(bytes.len() as u8);
        packet.extend_from_slice(bytes);
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}

pub fn first_a_record(message: &[u8]) -> Option<std::net::Ipv4Addr> {
    if message.len() < 12 {
        return None;
    }
    let questions = u16::from_be_bytes([message[4], message[5]]);
    let answers = u16::from_be_bytes([message[6], message[7]]);
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(message, offset)?;
        offset += 4;
    }
    for _ in 0..answers {
        offset = skip_name(message, offset)?;
        if offset + 10 > message.len() {
            return None;
        }
        let kind = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let len = u16::from_be_bytes([message[offset + 8], message[offset + 9]]) as usize;
        offset += 10;
        if offset + len > message.len() {
            return None;
        }
        if kind == 1 && len == 4 {
            return Some(std::net::Ipv4Addr::new(
                message[offset],
                message[offset + 1],
                message[offset + 2],
                message[offset + 3],
            ));
        }
        offset += len;
    }
    None
}

fn skip_name(message: &[u8], mut offset: usize) -> Option<usize> {
    let mut hops = 0;
    loop {
        if offset >= message.len() || hops > 16 {
            return None;
        }
        let len = message[offset];
        if len == 0 {
            return Some(offset + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(offset + 2);
        }
        offset += 1 + len as usize;
        hops += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn dial_to(addr: SocketAddr) -> DialFut {
        Box::pin(async move { TcpStream::connect(addr).await })
    }

    #[tokio::test]
    async fn rejects_missing_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected = basic_token("laneora", "secret");
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            handle_proxy(sock, &expected, |_| dial_to("127.0.0.1:1".parse().unwrap()))
                .await
                .unwrap();
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"CONNECT one.dat.com:443 HTTP/1.1\r\nHost: one.dat.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(text.contains("407"), "{text}");
    }

    #[tokio::test]
    async fn connect_tunnels_bytes() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expected = basic_token("laneora", "secret");
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            handle_proxy(sock, &expected, move |_| dial_to(echo_addr))
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let auth = basic_token("laneora", "secret");
        let request = format!("CONNECT one.dat.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 128];
        let n = client.read(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(text.contains("200"), "{text}");
        client.write_all(b"ping").await.unwrap();
        let mut pong = [0u8; 4];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"ping");
    }

    #[test]
    fn dns_query_and_answer_round_trip_shape() {
        let query = dns_query(0x1234, "one.dat.com");
        assert_eq!(&query[..2], &0x1234u16.to_be_bytes());
        assert!(query.ends_with(&[0, 1, 0, 1]));
        let message = [
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, b'a',
            0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x04, 1, 2, 3, 4,
        ];
        assert_eq!(
            first_a_record(&message).unwrap(),
            std::net::Ipv4Addr::new(1, 2, 3, 4)
        );
    }

    #[test]
    fn watchdog_messages_fire_on_change_and_failure() {
        let mut previous = String::new();
        let first = ip_change_message(&mut previous, "1.2.3.4", "Ashburn", "US").unwrap();
        assert!(first.contains("1.2.3.4"));
        assert!(ip_change_message(&mut previous, "1.2.3.4", "Ashburn", "US").is_none());
        let next = ip_change_message(&mut previous, "5.6.7.8", "Dallas", "US").unwrap();
        assert!(next.contains("5.6.7.8"));
        assert!(tunnel_down_message("no route").contains("Kill-switch"));
    }
}
