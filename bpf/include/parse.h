#pragma once

#include "common.h"
#include "mup_abi.h"

#define MUP_ETH_P_IPV4 0x0800
#define MUP_IPPROTO_ICMP 1
#define MUP_IPPROTO_UDP 17

struct mup_packet {
	struct ethhdr *ethernet;
	struct mup_iphdr *ipv4;
	void *packet_end;
	void *data_end;
	void *l4;
	__u8 *payload;
	__u32 payload_length;
	__u16 source_port;
	__u16 destination_port;
	__u16 server_port;
	__u8 transport;
};

/*
 * Clang merges the two loads into one 16-bit load and a byte swap. The
 * verifier of Linux 6.8 loses all bounds of a byte swap result, and then
 * rejects the packet pointer math with the value. The mask after the barrier
 * gives the verifier the 16-bit bound again.
 */
static __always_inline __u16 mup_read_be16(const __u8 *bytes)
{
	__u32 value = ((__u32)bytes[0] << 8) | bytes[1];

	asm volatile("" : "+r"(value));
	return value & 0xffff;
}

/*
 * The verifier learns packet bounds only from comparisons against
 * skb->data_end. packet_end, which comes from the IPv4 total length, gives
 * the protocol bound, so every access checks both.
 */
static __always_inline int mup_payload_fits(const struct mup_packet *packet,
					    __u32 length)
{
	return packet->payload + length <= (__u8 *)packet->data_end &&
	       packet->payload + length <= (__u8 *)packet->packet_end;
}

static __always_inline int parse_ipv4_l4(struct __sk_buff *skb, struct mup_packet *packet)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *ethernet = data;

	if ((void *)(ethernet + 1) > data_end)
		return MUP_DROP_MALFORMED_IPV4;
	if (mup_read_be16((const __u8 *)&ethernet->protocol) != MUP_ETH_P_IPV4)
		return MUP_TCX_NEXT;

	struct mup_iphdr *ipv4 = (void *)(ethernet + 1);
	if ((void *)(ipv4 + 1) > data_end)
		return MUP_DROP_MALFORMED_IPV4;
	if ((ipv4->version_ihl >> 4) != 4)
		return MUP_DROP_MALFORMED_IPV4;
	if ((ipv4->version_ihl & 0x0f) != 5)
		return MUP_DROP_IPV4_OPTIONS;
	if (mup_read_be16((const __u8 *)&ipv4->fragment_offset) & 0x3fff)
		return MUP_DROP_IPV4_FRAGMENT;

	__u16 total_length = mup_read_be16((const __u8 *)&ipv4->total_length);
	if (total_length < sizeof(*ipv4))
		return MUP_DROP_MALFORMED_IPV4;
	void *packet_end = (void *)ipv4 + total_length;
	if (packet_end > data_end)
		return MUP_DROP_MALFORMED_IPV4;

	packet->ethernet = ethernet;
	packet->ipv4 = ipv4;
	packet->packet_end = packet_end;
	packet->data_end = data_end;
	packet->l4 = (void *)(ipv4 + 1);
	if (ipv4->protocol == MUP_IPPROTO_UDP) {
		struct mup_udphdr *udp = packet->l4;
		if ((void *)(udp + 1) > data_end || (void *)(udp + 1) > packet_end)
			return MUP_DROP_MALFORMED_L4;
		__u16 udp_length = mup_read_be16((const __u8 *)&udp->length);
		if (udp_length < sizeof(*udp) || (void *)udp + udp_length != packet_end)
			return MUP_DROP_MALFORMED_L4;
		packet->transport = MUP_TRANSPORT_UDP;
		packet->source_port = mup_read_be16((const __u8 *)&udp->source);
		packet->destination_port = mup_read_be16((const __u8 *)&udp->destination);
		packet->server_port = packet->destination_port;
		packet->payload = (void *)(udp + 1);
	} else if (ipv4->protocol == MUP_IPPROTO_ICMP) {
		struct mup_icmphdr *icmp = packet->l4;
		if ((void *)(icmp + 1) > data_end || (void *)(icmp + 1) > packet_end)
			return MUP_DROP_MALFORMED_L4;
		packet->transport = MUP_TRANSPORT_ICMP;
		packet->source_port = 0;
		packet->destination_port = 0;
		packet->server_port = mup_read_be16((const __u8 *)&icmp->identifier);
		packet->payload = (void *)(icmp + 1);
	} else {
		return MUP_TCX_NEXT;
	}
	packet->payload_length = (__u8 *)packet_end - packet->payload;
	return MUP_DROP_NONE;
}

static __always_inline int validate_wg(const struct mup_packet *packet, int expect_peer_token, __u32 *peer_token)
{
	if (!mup_payload_fits(packet, 4))
		return MUP_DROP_WG_LENGTH;
	const __u8 *wireguard = packet->payload;
	__u8 type = wireguard[0];
	if (type == 1 && packet->payload_length != 148)
		return MUP_DROP_WG_LENGTH;
	if (type == 2 && packet->payload_length != 92)
		return MUP_DROP_WG_LENGTH;
	if (type == 3 && packet->payload_length != 64)
		return MUP_DROP_WG_LENGTH;
	if (type == 4 && (packet->payload_length < 32 || (packet->payload_length & 15)))
		return MUP_DROP_WG_LENGTH;
	if (type < 1 || type > 4)
		return MUP_DROP_WG_TYPE;

	__u32 token = ((__u32)wireguard[1] << 16) | ((__u32)wireguard[2] << 8) | wireguard[3];
	if (expect_peer_token) {
		if (token == 0 || token > MUP_MAX_PEER_TOKEN)
			return MUP_DROP_WG_RESERVED;
		*peer_token = token;
	} else if (token != 0) {
		return MUP_DROP_WG_RESERVED;
	}
	return MUP_DROP_NONE;
}

static __always_inline int is_mup_control(const struct mup_packet *packet)
{
	const __u8 *payload = packet->payload;

	if (packet->payload_length != MUP_CONTROL_FRAME_LEN ||
	    !mup_payload_fits(packet, MUP_CONTROL_FRAME_LEN))
		return 0;
	return payload[0] == 0x4d && payload[1] == 0x55 &&
	       payload[2] == 0x50 && payload[3] == 0x43 &&
	       payload[4] == MUP_ABI_VERSION &&
	       payload[8] == 0 && payload[9] == MUP_CONTROL_FRAME_LEN;
}
