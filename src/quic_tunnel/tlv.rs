use anyhow::{bail, ensure, Result};
use std::convert::From;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

pub const TYPE_TCP_CONNECT: u8 = 0;
pub const TYPE_TCP_CONNECT_OK: u8 = 1;
pub const TYPE_ERROR: u8 = 2;
pub const TYPE_END: u8 = 255;

pub const ERROR_TYPE_PROTOCOL_VIOLATION: u8 = 0;
pub const ERROR_TYPE_ICMP_PKT_RECV: u8 = 1;
pub const ERROR_TYPE_MALFORMED_TLV_RECV: u8 = 2;
pub const ERROR_TYPE_NETWORK_FAILURE: u8 = 3;

pub fn new_tcp_connect(buf: &mut [u8], addr: &SocketAddr) -> Result<usize> {
    ensure!(buf.len() >= 20, "size of buffer needs to be at least 20");

    // remote tcp IP address can't be multicast, broadcast or loopback address
    // TODO: need to check for broadcast IP

    // commented this out for local testing
    // ensure!(!addr.ip().is_loopback(), "loopback address is not allowed");

    ensure!(
        !addr.ip().is_multicast(),
        "multicast address is not allowed"
    );

    // Type
    buf[0] = TYPE_TCP_CONNECT;

    // Length
    buf[1] = 20;

    // Remote Peer Port
    buf[2..4].copy_from_slice(&addr.port().to_be_bytes());

    // Remote Peer IP Address
    // IPv4 addresses MUST be encoded using the IPv4-Mapped
    // IPv6 Address format defined in [RFC4291].
    let ipv6 = match addr.ip() {
        IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped(),
        IpAddr::V6(ipv6) => ipv6,
    };

    buf[4..20].copy_from_slice(&ipv6.octets());

    Ok(20)
}

pub fn new_tcp_connect_ok(buf: &mut [u8]) -> Result<usize> {
    // Type of TLV
    buf[0] = TYPE_TCP_CONNECT_OK;

    // Length
    buf[1] = 2;

    Ok(2)
}

pub fn new_end_tlv(buf: &mut [u8]) -> Result<usize> {
    // Type of TLV
    buf[0] = TYPE_END;

    // Length
    buf[1] = 2;

    Ok(2)
}

pub fn new_error_tlv(buf: &mut [u8]) -> Result<usize> {
    // Type of TLV
    buf[0] = TYPE_ERROR;

    let protocol_violation: u16 = 0x0;
    // let ICMP_packet_received: u16 = 0x1;
    // let malformed_tlv: u16 = 0x2;
    // let network_failure: u16 = 0x3;

    buf[2..4].copy_from_slice(&protocol_violation.to_be_bytes());

    buf[1] = 4;

    Ok(4)
}

pub fn is_tcp_connect_ok(buf: &[u8]) -> bool {
    return buf[0] == TYPE_TCP_CONNECT_OK;
}

pub fn parse_tcp_connect(buf: &[u8]) -> Result<SocketAddr> {
    if buf[0] != TYPE_TCP_CONNECT {
        bail!("Invalid TCP_CONNECT tlv");
    }
    let port = u16::from_be_bytes(buf[2..4].try_into()?);
    let ip_buf: [u8; 16] = buf[4..20].try_into()?;

    let ip = Ipv6Addr::from(ip_buf);

    Ok(SocketAddr::new(IpAddr::V6(ip), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn new_tcp_connect_v4_test() {
        let mut buf: [u8; 20] = [0; 20];
        let r = new_tcp_connect(&mut buf, &"10.0.0.1:8080".parse().unwrap());

        assert_eq!(20, r.unwrap());
        assert_eq!(TYPE_TCP_CONNECT, buf[0]);
        assert_eq!(20, buf[1]);
        assert_eq!([31, 144], &buf[2..4]);
        assert_eq!([0; 10], &buf[4..14]);
        assert_eq!([255; 2], &buf[14..16]);
        assert_eq!([10, 0, 0, 1], &buf[16..20]);
    }

    #[test]
    #[should_panic]
    fn new_tcp_connect_loopback_test() {
        let mut buf: [u8; 20] = [0; 20];
        new_tcp_connect(&mut buf, &"127.0.0.1:8080".parse().unwrap()).unwrap();
    }

    #[test]
    fn new_tcp_connect_ok_test() {
        let mut buf: [u8; 12] = [0; 12];
        let r = new_tcp_connect_ok(&mut buf);

        assert_eq!(2, r.unwrap());
        assert_eq!(TYPE_TCP_CONNECT_OK, buf[0]);
        assert_eq!(2, buf[1]);
    }

    #[test]
    fn parse_tcp_connect_test() {
        let mut buf: [u8; 20] = [0; 20];
        let _ = new_tcp_connect(&mut buf, &"10.0.0.1:8080".parse().unwrap());
        let r = parse_tcp_connect(&buf);

        assert_eq!(8080, r.as_ref().unwrap().port());
        assert_eq!(
            "10.0.0.1".parse::<Ipv4Addr>().unwrap().to_ipv6_mapped(),
            r.as_ref().unwrap().ip()
        );
    }
}
