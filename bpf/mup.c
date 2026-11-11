//go:build ignore

#include "common.h"
#include "mup_abi.h"
#include "parse.h"
#include "rewrite.h"

char __license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct client_config_v1);
} client_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	MUP_PINNED;
	__type(key, __be16);
	__type(value, struct path_group_v1);
} path_groups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct server_config_v1);
} server_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	MUP_PINNED;
	__type(key, struct client_key_v1);
	__type(value, struct registration_value_v1);
} registration_by_key SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	MUP_PINNED;
	__type(key, struct registered_path_key_v1);
	__type(value, struct registered_path_value_v1);
} registered_paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	MUP_PINNED;
	__type(key, struct peer_endpoint_key_v1);
	__type(value, struct peer_token_value_v1);
} client_peer_by_endpoint SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	MUP_PINNED;
	__type(key, __be32);
	__type(value, struct peer_endpoint_value_v1);
} client_endpoint_by_token SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 4095);
	MUP_PINNED;
	__type(value, __be32);
} free_peer_tokens SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 41000);
	MUP_PINNED;
	__type(key, struct server_route_key_v1);
	__type(value, struct server_route_value_v1);
} server_route_by_key SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 41000);
	MUP_PINNED;
	__type(key, __be16);
	__type(value, struct server_reverse_value_v1);
} server_route_by_port SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 41000);
	MUP_PINNED;
	__type(value, __be16);
} free_target_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct path_config_v1);
} path_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct path_state_v1);
} path_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	MUP_PINNED;
	__type(key, struct duplicate_key_v1);
	__type(value, __u64);
} duplicate_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 3);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, __u32);
} encap_programs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MUP_DROP_REASON_COUNT);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
	MUP_PINNED;
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MUP_DROP_REASON_COUNT);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct event_limit_v1);
} event_limits SEC(".maps");

#define MUP_DUPLICATE_WINDOW_NS 2000000000ULL
#define MUP_EVENT_WINDOW_NS 60000000000ULL
#define MUP_EVENT_LIMIT 10U

static __always_inline void emit_drop_event(struct __sk_buff *skb, __u32 reason)
{
	struct event_limit_v1 *limiter;
	struct event_v1 *event;
	__u64 now;
	int allowed = 0;

	if (reason != MUP_DROP_PEER_TOKEN_POOL &&
	    reason != MUP_DROP_TARGET_PORT_POOL &&
	    reason != MUP_DROP_MAP_INVARIANT)
		return;
	limiter = bpf_map_lookup_elem(&event_limits, &reason);
	if (!limiter)
		return;
	now = bpf_ktime_get_ns();
	bpf_spin_lock(&limiter->lock);
	if (now < limiter->window_started_ns ||
	    now - limiter->window_started_ns >= MUP_EVENT_WINDOW_NS) {
		limiter->window_started_ns = now;
		limiter->emitted = 0;
	}
	if (limiter->emitted < MUP_EVENT_LIMIT) {
		limiter->emitted++;
		allowed = 1;
	}
	bpf_spin_unlock(&limiter->lock);
	if (!allowed)
		return;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return;
	*event = (struct event_v1){};
	event->timestamp_ns = now;
	event->reason = reason;
	event->ifindex = skb->ifindex;
	bpf_ringbuf_submit(event, 0);
}

static __always_inline void count_reason(__u32 reason)
{
	__u64 *counter;

	if (reason <= MUP_DROP_NONE || reason >= MUP_DROP_REASON_COUNT)
		return;
	counter = bpf_map_lookup_elem(&stats, &reason);
	if (counter)
		*counter += 1;
}

static __always_inline int count_and_drop(struct __sk_buff *skb, __u32 reason)
{
	count_reason(reason);
	emit_drop_event(skb, reason);
	return TC_ACT_SHOT;
}

static __always_inline int get_or_create_client_route(
	const struct peer_endpoint_key_v1 *endpoint,
	__u32 ifindex,
	__u32 *peer_token)
{
	struct peer_token_value_v1 *existing;
	struct peer_token_value_v1 candidate = {};
	struct peer_endpoint_value_v1 reverse = {};
	__u64 now = bpf_ktime_get_ns();
	__u32 allocated = 0;
	long update_error;

	existing = bpf_map_lookup_elem(&client_peer_by_endpoint, endpoint);
	if (existing) {
		existing->last_seen_ns = now;
		*peer_token = existing->peer_token;
		return MUP_DROP_NONE;
	}

	if (bpf_map_pop_elem(&free_peer_tokens, &allocated))
		return MUP_DROP_PEER_TOKEN_POOL;
	if (allocated == 0 || allocated > MUP_MAX_PEER_TOKEN) {
		bpf_map_push_elem(&free_peer_tokens, &allocated, BPF_ANY);
		return MUP_DROP_MAP_INVARIANT;
	}

	candidate.peer_token = allocated;
	candidate.last_seen_ns = now;
	update_error = bpf_map_update_elem(&client_peer_by_endpoint, endpoint,
					   &candidate, BPF_NOEXIST);
	if (update_error) {
		bpf_map_push_elem(&free_peer_tokens, &allocated, BPF_ANY);
		existing = bpf_map_lookup_elem(&client_peer_by_endpoint, endpoint);
		if (!existing)
			return MUP_DROP_MAP_INVARIANT;
		existing->last_seen_ns = now;
		*peer_token = existing->peer_token;
		return MUP_DROP_NONE;
	}

	reverse.endpoint = *endpoint;
	reverse.ifindex = ifindex;
	reverse.last_seen_ns = now;
	update_error = bpf_map_update_elem(&client_endpoint_by_token, &allocated,
					   &reverse, BPF_NOEXIST);
	if (update_error) {
		bpf_map_delete_elem(&client_peer_by_endpoint, endpoint);
		bpf_map_push_elem(&free_peer_tokens, &allocated, BPF_ANY);
		return MUP_DROP_MAP_INVARIANT;
	}

	*peer_token = allocated;
	return MUP_DROP_NONE;
}

static __always_inline struct path_config_v1 *select_client_path(
	const struct path_group_v1 *group, __u32 peer_token)
{
	struct path_state_v1 *state;
	struct path_config_v1 *path;
	struct path_config_v1 *selected = 0;
	__u32 state_key = 0;
	__u32 selected_index = 0;
	__u32 healthy_count = 0;
	__u32 usable_mask;
	__u8 selected_priority = 0xff;

	state = bpf_map_lookup_elem(&path_state, &state_key);
	if (!state)
		return 0;
	usable_mask = state->healthy_mask & group->path_mask;
	if (!usable_mask)
		return 0;

	if (group->mode == MUP_MODE_BALANCER) {
#pragma clang loop unroll(full)
		for (int index = 0; index < 8; index++) {
			if (!(usable_mask & (1U << index)))
				continue;
			__u32 key = index;
			path = bpf_map_lookup_elem(&path_config, &key);
			if (path && path->destination_ip && path->ifindex)
				healthy_count++;
		}
		if (!healthy_count)
			return 0;
		__u32 hash = peer_token * 0x9e3779b1U ^ usable_mask * 0x85ebca6bU;
		hash ^= hash >> 16;
		__u32 ordinal = hash % healthy_count;
		healthy_count = 0;
#pragma clang loop unroll(full)
		for (int index = 0; index < 8; index++) {
			if (!(usable_mask & (1U << index)))
				continue;
			__u32 key = index;
			path = bpf_map_lookup_elem(&path_config, &key);
			if (!path || !path->destination_ip || !path->ifindex)
				continue;
			if (healthy_count == ordinal)
				return path;
			healthy_count++;
		}
		return 0;
	}

#pragma clang loop unroll(full)
	for (int index = 0; index < 8; index++) {
		if (!(usable_mask & (1U << index)))
			continue;
		__u32 key = index;
		path = bpf_map_lookup_elem(&path_config, &key);
		if (!path || !path->destination_ip || !path->ifindex)
			continue;
		if (!selected || path->priority < selected_priority) {
			selected = path;
			selected_priority = path->priority;
			selected_index = index;
		}
	}
	if (!selected)
		return 0;
	return bpf_map_lookup_elem(&path_config, &selected_index);
}

static __always_inline int is_direct_client_source(
	const struct mup_packet *packet, __u32 path_mask)
{
	struct path_config_v1 *path;
	__u16 observed_port = packet->transport == MUP_TRANSPORT_UDP ?
				  packet->source_port : packet->server_port;

#pragma clang loop unroll(full)
	for (int index = 0; index < 8; index++) {
		if (!(path_mask & (1U << index)))
			continue;
		__u32 key = index;
		path = bpf_map_lookup_elem(&path_config, &key);
		if (!path)
			continue;
		if (path->destination_ip == packet->ipv4->source &&
		    path->server_port == observed_port &&
		    path->transport == packet->transport)
			return 1;
	}
	return 0;
}

static __always_inline int is_client_icmp_port(
	const struct mup_packet *packet)
{
	struct path_config_v1 *path;

#pragma clang loop unroll(full)
	for (int index = 0; index < 8; index++) {
		__u32 key = index;
		path = bpf_map_lookup_elem(&path_config, &key);
		if (path && path->destination_ip &&
		    path->transport == MUP_TRANSPORT_ICMP &&
		    path->server_port == packet->server_port)
			return 1;
	}
	return 0;
}

static __always_inline int redirect_packet(__u32 ifindex)
{
	if (!ifindex)
		return TC_ACT_SHOT;
	return bpf_redirect_neigh(ifindex, 0, 0, 0);
}

static __always_inline int rewrite_for_path(
	struct mup_packet *packet,
	__u16 listen_port,
	const struct path_config_v1 *path,
	__u32 peer_token)
{
	if (path->transport == MUP_TRANSPORT_UDP)
		return mup_rewrite_udp(packet, path->source_ip,
				       path->destination_ip,
				       listen_port,
				       path->server_port);
	if (path->transport == MUP_TRANSPORT_ICMP)
		return mup_rewrite_icmp(packet, path->source_ip,
					path->destination_ip,
					MUP_ICMP_ECHO_REQUEST,
					path->server_port,
					(__u16)peer_token);
	return -2;
}

static __always_inline int prepare_clone_l2(
	struct __sk_buff *skb,
	const struct mup_packet *packet,
	__u32 expected_ifindex)
{
	struct bpf_fib_lookup fib = {};

	fib.family = AF_INET;
	fib.l4_protocol = packet->ipv4->protocol;
	fib.tot_len = mup_read_be16((const __u8 *)&packet->ipv4->total_length);
	fib.ifindex = expected_ifindex;
	fib.tos = packet->ipv4->tos;
	fib.ipv4_src = packet->ipv4->source;
	fib.ipv4_dst = packet->ipv4->destination;
	if (packet->transport == MUP_TRANSPORT_UDP) {
		struct mup_udphdr *udp = packet->l4;

		fib.sport = udp->source;
		fib.dport = udp->destination;
	}
	if (bpf_fib_lookup(skb, &fib, sizeof(fib),
			   BPF_FIB_LOOKUP_OUTPUT) != BPF_FIB_LKUP_RET_SUCCESS)
		return MUP_DROP_FIB;
	if (fib.ifindex != expected_ifindex)
		return MUP_DROP_FIB;

#pragma clang loop unroll(full)
	for (int index = 0; index < 6; index++) {
		packet->ethernet->source[index] = fib.smac[index];
		packet->ethernet->destination[index] = fib.dmac[index];
	}
	return MUP_DROP_NONE;
}

static __always_inline int burst_client_packet(
	struct __sk_buff *skb,
	struct mup_packet *packet,
	__u16 listen_port,
	__u32 path_mask,
	__u32 peer_token)
{
	struct path_state_v1 *state;
	struct path_config_v1 *mapped_path;
	struct path_config_v1 path = {};
	__u32 state_key = 0;
	__u32 healthy_mask;
	int final_index = -1;
	int cloned = 0;

	state = bpf_map_lookup_elem(&path_state, &state_key);
	if (!state)
		return count_and_drop(skb, MUP_DROP_NO_PATH);
	healthy_mask = state->healthy_mask & path_mask;
	if (!healthy_mask)
		return count_and_drop(skb, MUP_DROP_NO_PATH);

#pragma clang loop unroll(full)
	for (int index = 0; index < 8; index++) {
		__u32 key = index;

		if (!(healthy_mask & (1U << index)))
			continue;
		mapped_path = bpf_map_lookup_elem(&path_config, &key);
		if (mapped_path && mapped_path->destination_ip &&
		    mapped_path->ifindex &&
		    mapped_path->transport <= MUP_TRANSPORT_ICMP)
			final_index = index;
	}
	if (final_index < 0)
		return count_and_drop(skb, MUP_DROP_NO_PATH);

#pragma clang loop unroll(full)
	for (int index = 0; index < 8; index++) {
		__u32 key = index;
		int result;

		if (!(healthy_mask & (1U << index)))
			continue;
		mapped_path = bpf_map_lookup_elem(&path_config, &key);
		if (!mapped_path || !mapped_path->destination_ip ||
		    !mapped_path->ifindex ||
		    mapped_path->transport > MUP_TRANSPORT_ICMP)
			continue;
		path = *mapped_path;
		result = rewrite_for_path(packet, listen_port, &path,
					     peer_token);
		if (result == -2)
			return count_and_drop(skb, MUP_DROP_TRANSPORT);
		if (result)
			return count_and_drop(skb, MUP_DROP_CHECKSUM);

		if (index == final_index)
			return redirect_packet(path.ifindex);

		result = prepare_clone_l2(skb, packet, path.ifindex);
		if (result != MUP_DROP_NONE) {
			count_reason(result);
			continue;
		}
		if (bpf_clone_redirect(skb, path.ifindex, 0))
			count_reason(MUP_DROP_NEIGHBOR);
		else
			cloned++;

		/*
		 * clone_redirect may reallocate skb storage. No packet or map
		 * pointer obtained before the helper may be reused afterward.
		 */
		*packet = (struct mup_packet){};
		result = parse_ipv4_l4(skb, packet);
		if (result != MUP_DROP_NONE)
			return cloned ? TC_ACT_SHOT : count_and_drop(skb, result);
	}
	return cloned ? TC_ACT_SHOT : count_and_drop(skb, MUP_DROP_NO_PATH);
}

static __always_inline int same_server_route_key(
	const struct server_route_key_v1 *left,
	const struct server_route_key_v1 *right)
{
	return left->client.advertised_ip == right->client.advertised_ip &&
	       left->client.instance_nonce == right->client.instance_nonce &&
	       left->peer_token == right->peer_token;
}

static __always_inline int same_return_path(
	const struct server_route_value_v1 *left,
	const struct server_route_value_v1 *right)
{
	return left->server_port == right->server_port &&
	       left->transport == right->transport &&
	       left->flags == right->flags &&
	       left->path_id == right->path_id &&
	       left->client_source_ip == right->client_source_ip &&
	       left->server_local_ip == right->server_local_ip &&
	       left->return_ip == right->return_ip &&
	       left->ifindex == right->ifindex;
}

/*
 * Downstream packets follow the path of the latest accepted upstream packet,
 * so a client path failover also moves the return path. The reverse entry is
 * replaced as a whole so that a concurrent downstream packet never reads a mix
 * of two paths. Broken pairs are left for the Go invariant repair.
 */
static __always_inline void refresh_server_route(
	struct server_route_value_v1 *existing,
	const struct server_route_key_v1 *route_key,
	const struct server_route_value_v1 *observed,
	__u64 now)
{
	struct server_reverse_value_v1 *current;
	struct server_reverse_value_v1 updated = {};
	__u16 target_port = existing->target_port;

	existing->last_seen_ns = now;
	current = bpf_map_lookup_elem(&server_route_by_port, &target_port);
	if (!current || !same_server_route_key(&current->route_key, route_key) ||
	    same_return_path(&current->route_value, observed))
		return;

	updated.route_key = *route_key;
	updated.route_value = *observed;
	updated.route_value.target_port = target_port;
	updated.route_value.last_seen_ns = now;
	if (bpf_map_update_elem(&server_route_by_port, &target_port, &updated,
				BPF_EXIST))
		return;
	*existing = updated.route_value;
}

static __always_inline int get_or_create_server_route(
	const struct server_route_key_v1 *route_key,
	const struct server_route_value_v1 *observed,
	__u16 *target_port)
{
	struct server_route_value_v1 *existing;
	struct server_route_value_v1 candidate = *observed;
	struct server_reverse_value_v1 reverse = {};
	__u64 now = bpf_ktime_get_ns();
	__u16 allocated = 0;
	long update_error;

	existing = bpf_map_lookup_elem(&server_route_by_key, route_key);
	if (existing) {
		*target_port = existing->target_port;
		refresh_server_route(existing, route_key, observed, now);
		return MUP_DROP_NONE;
	}

	if (bpf_map_pop_elem(&free_target_ports, &allocated))
		return MUP_DROP_TARGET_PORT_POOL;
	if (allocated == 0) {
		bpf_map_push_elem(&free_target_ports, &allocated, BPF_ANY);
		return MUP_DROP_MAP_INVARIANT;
	}

	candidate.target_port = allocated;
	candidate.last_seen_ns = now;
	update_error = bpf_map_update_elem(&server_route_by_key, route_key,
					   &candidate, BPF_NOEXIST);
	if (update_error) {
		bpf_map_push_elem(&free_target_ports, &allocated, BPF_ANY);
		existing = bpf_map_lookup_elem(&server_route_by_key, route_key);
		if (!existing)
			return MUP_DROP_MAP_INVARIANT;
		existing->last_seen_ns = now;
		*target_port = existing->target_port;
		return MUP_DROP_NONE;
	}

	reverse.route_key = *route_key;
	reverse.route_value = candidate;
	update_error = bpf_map_update_elem(&server_route_by_port, &allocated,
					   &reverse, BPF_NOEXIST);
	if (update_error) {
		bpf_map_delete_elem(&server_route_by_key, route_key);
		bpf_map_push_elem(&free_target_ports, &allocated, BPF_ANY);
		return MUP_DROP_MAP_INVARIANT;
	}

	*target_port = allocated;
	return MUP_DROP_NONE;
}

static __always_inline int check_and_record_duplicate(
	const struct server_route_key_v1 *route,
	const struct mup_packet *packet,
	__u64 now)
{
	struct duplicate_key_v1 duplicate = {};
	__u64 *seen;

	if (!mup_payload_fits(packet, sizeof(duplicate.identity)))
		return MUP_DROP_WG_LENGTH;
	duplicate.route = *route;
#pragma clang loop unroll(full)
	for (int index = 0; index < sizeof(duplicate.identity); index++)
		duplicate.identity[index] = packet->payload[index];
	seen = bpf_map_lookup_elem(&duplicate_cache, &duplicate);
	if (seen && now >= *seen && now - *seen < MUP_DUPLICATE_WINDOW_NS)
		return MUP_DROP_DUPLICATE;
	if (bpf_map_update_elem(&duplicate_cache, &duplicate, &now, BPF_ANY))
		return MUP_DROP_MAP_INVARIANT;
	return MUP_DROP_NONE;
}

SEC("tc")
int mup_client_ingress(struct __sk_buff *skb)
{
	struct mup_packet packet = {};
	struct client_config_v1 *configuration;
	struct path_group_v1 *group;
	struct path_config_v1 *path;
	struct peer_endpoint_key_v1 endpoint = {};
	struct peer_endpoint_value_v1 *reverse;
	struct peer_token_value_v1 *forward;
	__u32 configuration_key = 0;
	__u32 peer_token = 0;
	int result;

	result = parse_ipv4_l4(skb, &packet);
	if (result != MUP_DROP_NONE)
		return MUP_TCX_NEXT;
	configuration = bpf_map_lookup_elem(&client_config, &configuration_key);
	if (!configuration)
		return MUP_TCX_NEXT;
	if (is_mup_control(&packet))
		return MUP_TCX_NEXT;

	peer_token = mup_read_peer_token(&packet);
	if (peer_token) {
		if (packet.ipv4->destination != configuration->advertised_ip)
			return MUP_TCX_NEXT;
		if (packet.transport == MUP_TRANSPORT_UDP) {
			if (!bpf_map_lookup_elem(&path_groups,
						 &packet.destination_port))
				return MUP_TCX_NEXT;
		} else {
			struct mup_icmphdr *icmp = packet.l4;
			if (icmp->type != MUP_ICMP_ECHO_REPLY || icmp->code != 0 ||
			    !is_client_icmp_port(&packet))
				return MUP_TCX_NEXT;
		}
		result = validate_wg(&packet, 1, &peer_token);
		if (result != MUP_DROP_NONE)
			return count_and_drop(skb, result);
		reverse = bpf_map_lookup_elem(&client_endpoint_by_token, &peer_token);
		if (!reverse)
			return count_and_drop(skb, MUP_DROP_ROUTE_MISS);
		/* The group of the peer decides which sources can answer it. */
		group = bpf_map_lookup_elem(&path_groups,
					    &reverse->endpoint.listen_port);
		if (!group)
			return count_and_drop(skb, MUP_DROP_DOWNSTREAM_SOURCE);
		if (group->flags & MUP_FLAG_RETURN_IP) {
			if (packet.ipv4->source != group->return_ip)
				return count_and_drop(skb, MUP_DROP_DOWNSTREAM_SOURCE);
		} else if (!is_direct_client_source(&packet, group->path_mask)) {
			return count_and_drop(skb, MUP_DROP_DOWNSTREAM_SOURCE);
		}
		reverse->last_seen_ns = bpf_ktime_get_ns();
		forward = bpf_map_lookup_elem(&client_peer_by_endpoint,
					      &reverse->endpoint);
		if (!forward || forward->peer_token != peer_token)
			return count_and_drop(skb, MUP_DROP_MAP_INVARIANT);
		forward->last_seen_ns = reverse->last_seen_ns;
		if (mup_clear_peer_token(&packet) ||
		    mup_rewrite_udp(&packet, reverse->endpoint.local_ip,
				    reverse->endpoint.source_ip,
				    reverse->endpoint.listen_port,
				    reverse->endpoint.source_port))
			return count_and_drop(skb, MUP_DROP_CHECKSUM);
		return redirect_packet(reverse->ifindex);
	}

	if (packet.transport != MUP_TRANSPORT_UDP)
		return MUP_TCX_NEXT;
	group = bpf_map_lookup_elem(&path_groups, &packet.destination_port);
	if (!group)
		return MUP_TCX_NEXT;
	result = validate_wg(&packet, 0, &peer_token);
	if (result != MUP_DROP_NONE)
		return count_and_drop(skb, result);

	endpoint.source_ip = packet.ipv4->source;
	endpoint.local_ip = packet.ipv4->destination;
	endpoint.source_port = packet.source_port;
	endpoint.listen_port = packet.destination_port;
	result = get_or_create_client_route(&endpoint, skb->ifindex, &peer_token);
	if (result != MUP_DROP_NONE)
		return count_and_drop(skb, result);
	/*
	 * Each read of the group mode is a separate value to the verifier, so
	 * one branch must decide the mode. A second read lets the verifier
	 * explore the single path case without a selected path.
	 */
	if (group->mode == MUP_MODE_BURST) {
		if (mup_set_peer_token(&packet, peer_token))
			return count_and_drop(skb, MUP_DROP_MAP_INVARIANT);
		return burst_client_packet(skb, &packet, endpoint.listen_port,
					   group->path_mask, peer_token);
	}
	path = select_client_path(group, peer_token);
	if (!path)
		return count_and_drop(skb, MUP_DROP_NO_PATH);
	if (mup_set_peer_token(&packet, peer_token))
		return count_and_drop(skb, MUP_DROP_MAP_INVARIANT);
	result = rewrite_for_path(&packet, endpoint.listen_port, path, peer_token);
	if (result == -2)
		return count_and_drop(skb, MUP_DROP_TRANSPORT);
	if (result)
		return count_and_drop(skb, MUP_DROP_CHECKSUM);

	return redirect_packet(path->ifindex);
}

SEC("tc")
int mup_server_ingress(struct __sk_buff *skb)
{
	struct mup_packet packet = {};
	struct server_config_v1 *configuration;
	struct registered_path_key_v1 path_key = {};
	struct registered_path_value_v1 *path;
	struct registration_value_v1 *registration;
	struct server_reverse_value_v1 *reverse;
	struct server_route_value_v1 *forward;
	struct server_route_key_v1 route_key = {};
	struct server_route_value_v1 observed = {};
	__u32 configuration_key = 0;
	__u32 peer_token = 0;
	__u16 target_port = 0;
	__u64 now;
	int result;

	result = parse_ipv4_l4(skb, &packet);
	if (result != MUP_DROP_NONE)
		return MUP_TCX_NEXT;
	configuration = bpf_map_lookup_elem(&server_config, &configuration_key);
	if (!configuration)
		return MUP_TCX_NEXT;

	if (packet.transport == MUP_TRANSPORT_UDP &&
	    packet.ipv4->source == configuration->target_ip &&
	    packet.ipv4->destination == configuration->source_ip &&
	    packet.source_port == configuration->target_port) {
		/*
		 * The target can also answer other programs on this host, for
		 * example a target on 127.0.0.1. A port without a route is not a
		 * mup port, so the packet goes to the next program.
		 */
		reverse = bpf_map_lookup_elem(&server_route_by_port,
					      &packet.destination_port);
		if (!reverse)
			return MUP_TCX_NEXT;
		result = validate_wg(&packet, 0, &peer_token);
		if (result != MUP_DROP_NONE)
			return count_and_drop(skb, result);
		now = bpf_ktime_get_ns();
		registration = bpf_map_lookup_elem(&registration_by_key,
						   &reverse->route_key.client);
		if (!registration || registration->expires_at_ns < now)
			return count_and_drop(skb, MUP_DROP_NOT_REGISTERED);
		reverse->route_value.last_seen_ns = now;
		forward = bpf_map_lookup_elem(&server_route_by_key,
					      &reverse->route_key);
		if (!forward || forward->target_port != packet.destination_port)
			return count_and_drop(skb, MUP_DROP_MAP_INVARIANT);
		forward->last_seen_ns = now;
		if (mup_set_peer_token(&packet, reverse->route_key.peer_token))
			return count_and_drop(skb, MUP_DROP_MAP_INVARIANT);
		if (reverse->route_value.transport == MUP_TRANSPORT_UDP) {
			__be32 source_ip =
				(reverse->route_value.flags & MUP_FLAG_RETURN_IP) ?
				reverse->route_value.return_ip :
				reverse->route_value.server_local_ip;
			if (mup_rewrite_udp(&packet, source_ip,
					    reverse->route_key.client.advertised_ip,
					    reverse->route_value.server_port,
					    registration->listen_port))
				return count_and_drop(skb, MUP_DROP_CHECKSUM);
		} else if (reverse->route_value.transport == MUP_TRANSPORT_ICMP) {
			__be32 source_ip;
			__be32 destination_ip;
			__u8 type;

			if (reverse->route_value.flags & MUP_FLAG_RETURN_IP) {
				source_ip = reverse->route_key.client.advertised_ip;
				destination_ip = reverse->route_value.return_ip;
				type = MUP_ICMP_ECHO_REQUEST;
			} else {
				source_ip = reverse->route_value.server_local_ip;
				destination_ip =
					reverse->route_key.client.advertised_ip;
				type = MUP_ICMP_ECHO_REPLY;
			}
			if (mup_rewrite_icmp(&packet, source_ip, destination_ip,
					     type, reverse->route_value.server_port,
					     (__u16)reverse->route_key.peer_token))
				return count_and_drop(skb, MUP_DROP_CHECKSUM);
		} else {
			return count_and_drop(skb, MUP_DROP_TRANSPORT);
		}
		return redirect_packet(reverse->route_value.ifindex);
	}

	if (packet.server_port != configuration->server_port)
		return MUP_TCX_NEXT;
	if (is_mup_control(&packet))
		return MUP_TCX_NEXT;
	if (packet.transport == MUP_TRANSPORT_ICMP) {
		struct mup_icmphdr *icmp = packet.l4;
		if (icmp->type != MUP_ICMP_ECHO_REQUEST || icmp->code != 0)
			return MUP_TCX_NEXT;
	}
	result = validate_wg(&packet, 1, &peer_token);
	if (result != MUP_DROP_NONE)
		return count_and_drop(skb, result);

	path_key.source_ip = packet.ipv4->source;
	path_key.local_ip = packet.ipv4->destination;
	path_key.server_port = packet.server_port;
	path_key.transport = packet.transport;
	path = bpf_map_lookup_elem(&registered_paths, &path_key);
	if (!path)
		return count_and_drop(skb, MUP_DROP_NOT_REGISTERED);
	now = bpf_ktime_get_ns();
	if (path->expires_at_ns < now)
		return count_and_drop(skb, MUP_DROP_NOT_REGISTERED);

	registration = bpf_map_lookup_elem(&registration_by_key, &path->client);
	if (!registration || registration->expires_at_ns < now)
		return count_and_drop(skb, MUP_DROP_NOT_REGISTERED);

	route_key.client = path->client;
	route_key.peer_token = peer_token;
	result = check_and_record_duplicate(&route_key, &packet, now);
	if (result != MUP_DROP_NONE)
		return count_and_drop(skb, result);
	observed.server_port = packet.server_port;
	observed.transport = packet.transport;
	observed.flags = registration->flags;
	observed.path_id = path->path_id;
	observed.client_source_ip = packet.ipv4->source;
	observed.server_local_ip = packet.ipv4->destination;
	observed.return_ip = registration->return_ip;
	observed.ifindex = skb->ifindex;
	result = get_or_create_server_route(&route_key, &observed, &target_port);
	if (result != MUP_DROP_NONE)
		return count_and_drop(skb, result);
	if (mup_clear_peer_token(&packet) ||
	    mup_rewrite_udp(&packet, configuration->source_ip,
			    configuration->target_ip, target_port,
			    configuration->target_port))
		return count_and_drop(skb, MUP_DROP_CHECKSUM);

	return redirect_packet(configuration->ifindex);
}

SEC("tc")
int mup_test_parse(struct __sk_buff *skb)
{
	struct mup_packet packet = {};
	return parse_ipv4_l4(skb, &packet);
}

SEC("tc")
int mup_test_validate_local(struct __sk_buff *skb)
{
	struct mup_packet packet = {};
	__u32 peer_token = 0;
	int result = parse_ipv4_l4(skb, &packet);

	if (result != MUP_DROP_NONE)
		return result;
	return validate_wg(&packet, 0, &peer_token);
}

SEC("tc")
int mup_test_validate_tunneled(struct __sk_buff *skb)
{
	struct mup_packet packet = {};
	__u32 peer_token = 0;
	int result = parse_ipv4_l4(skb, &packet);

	if (result != MUP_DROP_NONE)
		return result;
	return validate_wg(&packet, 1, &peer_token);
}

SEC("tc")
int mup_test_control(struct __sk_buff *skb)
{
	struct mup_packet packet = {};
	int result = parse_ipv4_l4(skb, &packet);

	if (result != MUP_DROP_NONE)
		return 0;
	return is_mup_control(&packet);
}
