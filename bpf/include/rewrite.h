#pragma once

#include "common.h"
#include "mup_abi.h"
#include "parse.h"

#define MUP_ICMP_ECHO_REPLY 0
#define MUP_ICMP_ECHO_REQUEST 8

/*
 * MUP changes only the IPv4 addresses and protocol, the 8-byte UDP or ICMP
 * header, and the peer token in WireGuard bytes 1 to 3. Each change updates
 * the transport checksum incrementally (RFC 1624), so the cost does not
 * depend on the payload length. A valid checksum stays valid, and a corrupt
 * one stays corrupt for the receiver to reject. protocol/rewrite.go mirrors
 * this file and tests the arithmetic.
 */

static __always_inline void mup_write_be16(__be16 *field, __u16 value)
{
	__u8 *bytes = (__u8 *)field;

	bytes[0] = value >> 8;
	bytes[1] = value;
}

/* Two folds reduce any 32-bit one's complement sum to 16 bits. */
static __always_inline __u16 mup_csum_fold(__u32 sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

static __always_inline void mup_refresh_ipv4_checksum(struct mup_iphdr *ipv4)
{
	const __u8 *bytes = (const __u8 *)ipv4;
	__u32 sum = 0;

	ipv4->checksum = 0;
#pragma clang loop unroll(full)
	for (int offset = 0; offset < sizeof(*ipv4); offset += 2)
		sum += mup_read_be16(bytes + offset);
	mup_write_be16(&ipv4->checksum, ~mup_csum_fold(sum));
}

/*
 * Sum of the words that the transport checksum covers, except the payload
 * and the checksum field: the UDP pseudo-header and UDP header, or the ICMP
 * header.
 */
static __always_inline __u32 mup_l4_header_sum(const struct mup_packet *packet)
{
	const __u8 *ipv4 = (const __u8 *)packet->ipv4;
	const __u8 *l4 = packet->l4;

	if (packet->transport == MUP_TRANSPORT_UDP)
		return mup_read_be16(ipv4 + 12) + mup_read_be16(ipv4 + 14) +
		       mup_read_be16(ipv4 + 16) + mup_read_be16(ipv4 + 18) +
		       MUP_IPPROTO_UDP + mup_read_be16(l4 + 4) +
		       mup_read_be16(l4) + mup_read_be16(l4 + 2) +
		       mup_read_be16(l4 + 4);
	return mup_read_be16(l4) + mup_read_be16(l4 + 4) + mup_read_be16(l4 + 6);
}

static __always_inline __u16 mup_l4_checksum(const struct mup_packet *packet)
{
	const __u8 *l4 = packet->l4;

	if (packet->transport == MUP_TRANSPORT_UDP)
		return mup_read_be16(l4 + 6);
	return mup_read_be16(l4 + 2);
}

/* A computed UDP checksum of zero is sent as 0xffff (RFC 768). */
static __always_inline void mup_write_l4_checksum(struct mup_packet *packet,
						  __u16 checksum)
{
	__u8 *l4 = packet->l4;

	if (packet->transport == MUP_TRANSPORT_UDP) {
		mup_write_be16((__be16 *)(l4 + 6), checksum ? checksum : 0xffff);
		return;
	}
	mup_write_be16((__be16 *)(l4 + 2), checksum);
}

/*
 * mup_write_peer_token stores a peer token in WireGuard bytes 1 to 3, or
 * zero to clear them, and updates the transport checksum. A UDP packet
 * without a checksum keeps it at zero, and the next rewrite drops it.
 */
static __always_inline int mup_write_peer_token(struct mup_packet *packet,
						__u32 peer_token)
{
	__u8 *payload = packet->payload;
	__u16 checksum;
	__u32 sum;

	if (!mup_payload_fits(packet, 4))
		return -1;
	checksum = mup_l4_checksum(packet);
	sum = (__u16)~checksum;
	sum += (__u16)~mup_csum_fold(mup_read_be16(payload) +
				     mup_read_be16(payload + 2));
	payload[1] = peer_token >> 16;
	payload[2] = peer_token >> 8;
	payload[3] = peer_token;
	sum += mup_read_be16(payload) + mup_read_be16(payload + 2);
	if (packet->transport == MUP_TRANSPORT_UDP && !checksum)
		return 0;
	mup_write_l4_checksum(packet, ~mup_csum_fold(sum));
	return 0;
}

static __always_inline int mup_set_peer_token(struct mup_packet *packet,
					      __u32 peer_token)
{
	if (peer_token == 0 || peer_token > MUP_MAX_PEER_TOKEN)
		return -1;
	return mup_write_peer_token(packet, peer_token);
}

static __always_inline int mup_clear_peer_token(struct mup_packet *packet)
{
	return mup_write_peer_token(packet, 0);
}

static __always_inline __u32 mup_read_peer_token(
	const struct mup_packet *packet)
{
	if (!mup_payload_fits(packet, 4))
		return 0;
	return ((__u32)packet->payload[1] << 16) |
	       ((__u32)packet->payload[2] << 8) |
	       packet->payload[3];
}

/*
 * mup_payload_sum derives the one's complement sum of the transport payload
 * from the current checksum. A UDP packet without a checksum has no sum to
 * derive, so MUP drops it.
 */
static __always_inline int mup_payload_sum(const struct mup_packet *packet,
					   __u32 *sum)
{
	__u16 checksum = mup_l4_checksum(packet);

	if (packet->transport == MUP_TRANSPORT_UDP && !checksum)
		return -1;
	*sum = (__u16)~checksum;
	*sum += (__u16)~mup_csum_fold(mup_l4_header_sum(packet));
	return 0;
}

static __always_inline void mup_finish_rewrite(struct mup_packet *packet,
					       __u32 payload_sum)
{
	mup_write_l4_checksum(packet, ~mup_csum_fold(payload_sum +
						     mup_l4_header_sum(packet)));
	mup_refresh_ipv4_checksum(packet->ipv4);
}

static __always_inline int mup_rewrite_udp(struct mup_packet *packet,
					   __be32 source_ip,
					   __be32 destination_ip,
					   __u16 source_port,
					   __u16 destination_port)
{
	struct mup_udphdr *udp = packet->l4;
	__u32 l4_length = (__u8 *)packet->packet_end - (__u8 *)udp;
	__u32 payload_sum;

	if ((void *)(udp + 1) > packet->data_end ||
	    (void *)(udp + 1) > packet->packet_end || l4_length > 0xffff)
		return -1;
	if (mup_payload_sum(packet, &payload_sum))
		return -1;
	packet->ipv4->source = source_ip;
	packet->ipv4->destination = destination_ip;
	packet->ipv4->protocol = MUP_IPPROTO_UDP;
	packet->transport = MUP_TRANSPORT_UDP;
	mup_write_be16(&udp->source, source_port);
	mup_write_be16(&udp->destination, destination_port);
	mup_write_be16(&udp->length, l4_length);
	mup_finish_rewrite(packet, payload_sum);
	return 0;
}

static __always_inline int mup_rewrite_icmp(struct mup_packet *packet,
					    __be32 source_ip,
					    __be32 destination_ip,
					    __u8 type,
					    __u16 identifier,
					    __u16 sequence)
{
	struct mup_icmphdr *icmp = packet->l4;
	__u32 payload_sum;

	if ((void *)(icmp + 1) > packet->data_end ||
	    (void *)(icmp + 1) > packet->packet_end)
		return -1;
	if (mup_payload_sum(packet, &payload_sum))
		return -1;
	packet->ipv4->source = source_ip;
	packet->ipv4->destination = destination_ip;
	packet->ipv4->protocol = MUP_IPPROTO_ICMP;
	packet->transport = MUP_TRANSPORT_ICMP;
	icmp->type = type;
	icmp->code = 0;
	mup_write_be16(&icmp->identifier, identifier);
	mup_write_be16(&icmp->sequence, sequence);
	mup_finish_rewrite(packet, payload_sum);
	return 0;
}
