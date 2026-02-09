use crate::messages::SmolPacket;
use smoltcp::wire::ip::checksum as ip_checksum;
use smoltcp::wire::{
    IpProtocol, IpRepr, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, IPV6_HEADER_LEN,
};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    Icmpv4Message, Icmpv4Packet, Icmpv4Repr, Icmpv6Message, Icmpv6Packet, Icmpv6Repr, IpProtocol,
    Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
};

pub(super) fn handle_icmpv4_echo_request(
    mut input_packet: Ipv4Packet<Vec<u8>>,
) -> Option<SmolPacket> {
    let src_addr = input_packet.src_addr();
    let dst_addr = input_packet.dst_addr();

    // Parsing ICMP Packet
    let mut input_icmpv4_packet = match Icmpv4Packet::new_checked(input_packet.payload_mut()) {
        Ok(p) => p,
        Err(e) => {
            log::debug!("Received invalid ICMPv4 packet: {e}");
            return None;
        }
    };

    // Checking that it is an ICMP Echo Request.
    if input_icmpv4_packet.msg_type() != Icmpv4Message::EchoRequest {
        log::debug!(
            "Unsupported ICMPv4 packet of type: {}",
            input_icmpv4_packet.msg_type()
        );
        return None;
    }

    // Creating fake response packet.
    let icmp_repr = Icmpv4Repr::EchoReply {
        ident: input_icmpv4_packet.echo_ident(),
        seq_no: input_icmpv4_packet.echo_seq_no(),
        data: input_icmpv4_packet.data_mut(),
    };
    let ip_repr = Ipv4Repr {
        // Directing fake reply back to the original source address.
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmp,
        payload_len: icmp_repr.buffer_len(),
        hop_limit: 255,
    };
    let buf = vec![0u8; ip_repr.buffer_len() + icmp_repr.buffer_len()];
    let mut output_ipv4_packet = Ipv4Packet::new_unchecked(buf);
    ip_repr.emit(&mut output_ipv4_packet, &ChecksumCapabilities::default());
    let mut output_ip_packet = SmolPacket::from(output_ipv4_packet);
    icmp_repr.emit(
        &mut Icmpv4Packet::new_unchecked(output_ip_packet.payload_mut()),
        &ChecksumCapabilities::default(),
    );
    Some(output_ip_packet)
}

pub(super) fn handle_icmpv6_echo_request(
    mut input_packet: Ipv6Packet<Vec<u8>>,
) -> Option<SmolPacket> {
    let src_addr = input_packet.src_addr();
    let dst_addr = input_packet.dst_addr();

    // Parsing ICMP Packet
    let mut input_icmpv6_packet = match Icmpv6Packet::new_checked(input_packet.payload_mut()) {
        Ok(p) => p,
        Err(e) => {
            log::debug!("Received invalid ICMPv6 packet: {e}");
            return None;
        }
    };

    match input_icmpv6_packet.msg_type() {
        Icmpv6Message::EchoRequest => (),
        Icmpv6Message::RouterSolicit => {
            // These happen in Linux local redirect mode, not investigated any further.
            log::debug!("Ignoring ICMPv6 router solicitation.");
            return None;
        }
        other => {
            log::debug!("Unsupported ICMPv6 packet of type: {other}");
            return None;
        }
    }

    // Creating fake response packet.
    let icmp_repr = Icmpv6Repr::EchoReply {
        ident: input_icmpv6_packet.echo_ident(),
        seq_no: input_icmpv6_packet.echo_seq_no(),
        data: input_icmpv6_packet.payload_mut(),
    };
    let ip_repr = Ipv6Repr {
        // Directing fake reply back to the original source address.
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmp,
        payload_len: icmp_repr.buffer_len(),
        hop_limit: 255,
    };
    let buf = vec![0u8; ip_repr.buffer_len() + icmp_repr.buffer_len()];
    let mut output_ipv6_packet = Ipv6Packet::new_unchecked(buf);
    ip_repr.emit(&mut output_ipv6_packet);
    let mut output_ip_packet = SmolPacket::from(output_ipv6_packet);
    icmp_repr.emit(
        // Directing fake reply back to the original source address.
        &dst_addr,
        &src_addr,
        &mut Icmpv6Packet::new_unchecked(output_ip_packet.payload_mut()),
        &ChecksumCapabilities::default(),
    );
    Some(output_ip_packet)
}

pub(super) fn build_icmp_port_unreachable(original: SmolPacket) -> Option<SmolPacket> {
    match original {
        SmolPacket::V4(packet) => build_icmpv4_port_unreachable(packet),
        SmolPacket::V6(packet) => build_icmpv6_port_unreachable(packet),
    }
}

fn build_icmpv4_port_unreachable(original: Ipv4Packet<Vec<u8>>) -> Option<SmolPacket> {
    let src_addr = original.src_addr();
    let dst_addr = original.dst_addr();
    let header_len = original.header_len() as usize;
    let original_bytes = original.into_inner();
    let copy_len = usize::min(original_bytes.len(), header_len + 8);
    let payload = &original_bytes[..copy_len];

    let icmp_len = 8 + payload.len();
    let ip_repr = Ipv4Repr {
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmp,
        payload_len: icmp_len,
        hop_limit: 255,
    };

    let buf = vec![0u8; IpRepr::Ipv4(ip_repr).buffer_len()];
    let mut output_packet = Ipv4Packet::new_unchecked(buf);
    ip_repr.emit(&mut output_packet, &ChecksumCapabilities::default());

    let icmp_payload = output_packet.payload_mut();
    icmp_payload[0] = 3; // Destination Unreachable
    icmp_payload[1] = 3; // Port Unreachable
    // checksum at [2..4], unused at [4..8] are already zero
    icmp_payload[8..8 + payload.len()].copy_from_slice(payload);

    let checksum = !ip_checksum::data(icmp_payload);
    icmp_payload[2..4].copy_from_slice(&checksum.to_be_bytes());

    Some(SmolPacket::from(output_packet))
}

fn build_icmpv6_port_unreachable(original: Ipv6Packet<Vec<u8>>) -> Option<SmolPacket> {
    let src_addr = original.src_addr();
    let dst_addr = original.dst_addr();
    let original_bytes = original.into_inner();
    let copy_len = usize::min(original_bytes.len(), IPV6_HEADER_LEN + 8);
    let payload = &original_bytes[..copy_len];

    let icmp_len = 8 + payload.len();
    let ip_repr = Ipv6Repr {
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmpv6,
        payload_len: icmp_len,
        hop_limit: 255,
    };

    let buf = vec![0u8; IpRepr::Ipv6(ip_repr).buffer_len()];
    let mut output_packet = Ipv6Packet::new_unchecked(buf);
    ip_repr.emit(&mut output_packet);

    let icmp_payload = output_packet.payload_mut();
    icmp_payload[0] = 1; // Destination Unreachable
    icmp_payload[1] = 4; // Port Unreachable
    // checksum at [2..4], unused at [4..8] are already zero
    icmp_payload[8..8 + payload.len()].copy_from_slice(payload);

    let checksum = ip_checksum::combine(&[
        ip_checksum::pseudo_header_v6(&dst_addr, &src_addr, IpProtocol::Icmpv6, icmp_len as u32),
        ip_checksum::data(icmp_payload),
    ]);
    let checksum = !checksum;
    icmp_payload[2..4].copy_from_slice(&checksum.to_be_bytes());

    Some(SmolPacket::from(output_packet))
}
