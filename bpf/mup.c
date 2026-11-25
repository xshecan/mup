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
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct server_ports_v1);
} server_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct target_ingress_v1);
} target_ingress SEC(".maps");

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
	__uint(max_entries, 4096);
	MUP_PINNED;
	__type(key, __be32);
	__type(value, __u32);
} client_routes_by_source SEC(".maps");

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
	__uint(max_entries, 8);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct path_return_v1);
} path_returns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct up_reflect_v1);
} up_reflect_members SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, __u32);
} up_reflect_cursor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct path_state_v1);
} path_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	MUP_PINNED;
	__type(key, struct reflector_key_v1);
	__type(value, struct reflector_pool_v1);
} reflector_pools SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, __u32);
} reflector_cursor SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	MUP_PINNED;
	__type(key, struct duplicate_key_v1);
	__type(value, __u64);
} duplicate_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct client_down_path_v1);
} client_down_paths SEC(".maps");

/* client_path_src holds the source range of each client path, by path slot. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct path_src_v1);
} client_path_src SEC(".maps");

/*
 * client_down_src holds the source range of each down path of the client, by
 * down path slot.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct path_src_v1);
} client_down_src SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	MUP_PINNED;
	__type(key, struct client_duplicate_key_v1);
	__type(value, __u64);
} client_duplicate_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	MUP_PINNED;
	__type(key, struct down_group_key_v1);
	__type(value, struct down_group_v1);
} server_down_groups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	MUP_PINNED;
	__type(key, struct down_path_key_v1);
	__type(value, struct down_path_v1);
} server_down_paths SEC(".maps");

/*
 * client_path_counters counts the data packets of the client paths. Index 0 to
 * 7 holds the packets that the client sent on each ingress path slot, and
 * index MUP_PATH_COUNTER_EGRESS_BASE plus a slot the packets that it accepted
 * from that egress path slot. The counters only grow, and Go reads their
 * differences, so a start of the daemon need not zero them.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MUP_PATH_COUNTERS);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct path_counter_v1);
} client_path_counters SEC(".maps");

/*
 * server_path_counters counts the data packets of each path of each client on
 * the server, in each direction. Go creates a counter when a path registers
 * and deletes it when the path goes away. The program adds only to a counter
 * that exists, so a packet never creates one.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 8192);
	MUP_PINNED;
	__type(key, struct path_counter_key_v1);
	__type(value, struct path_counter_v1);
} server_path_counters SEC(".maps");

/*
 * bridge_config holds the entries of the bridge. The port of a packet picks
 * the entry, and an entry with a zero server_ip is unused.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MUP_MAX_BRIDGES);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, struct bridge_config_v1);
} bridge_config SEC(".maps");

/* bridge_addresses holds the IPv4 addresses of the bridge host. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	MUP_PINNED;
	__type(key, __be32);
	__type(value, __u8);
} bridge_addresses SEC(".maps");

/*
 * bridge_allow holds the senders of wrapped replies of each entry: the server
 * of the entry, and the allow ranges of its configuration. The key starts with
 * the entry index, so each entry has its own senders.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 64 * MUP_MAX_BRIDGES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	MUP_PINNED;
	__type(key, struct bridge_allow_key_v1);
	__type(value, __u8);
} bridge_allow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MUP_BRIDGE_COUNTERS);
	MUP_PINNED;
	__type(key, __u32);
	__type(value, __u64);
} bridge_counters SEC(".maps");

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

/*
 * One chunk is the largest size that bpf_csum_diff takes in one call. The
 * chunks cover a payload of 9216 bytes, more than a jumbo frame.
 */
#define MUP_CSUM_CHUNK 512
#define MUP_CSUM_CHUNKS 18

struct csum_scratch {
	__u8 bytes[MUP_CSUM_CHUNK];
};

/* The scratch buffer holds no state, so it is not pinned. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct csum_scratch);
} csum_scratch SEC(".maps");

/*
 * send_scratch holds the large values of a send that would not fit on the
 * stack of a function that a program calls: the FIB lookup of a clone, and
 * the key of a down path. The key of a path counter has the same layout, so
 * it shares the place of the down path key. It holds no state, so it is not
 * pinned.
 */
struct send_scratch_layout {
	struct bpf_fib_lookup fib;
	union {
		struct down_path_key_v1 key;
		struct path_counter_key_v1 counter_key;
	};
};

/* bpf2go cannot describe the unions of bpf_fib_lookup, so the map holds words. */
struct send_scratch {
	__u64 words[(sizeof(struct send_scratch_layout) + 7) / 8];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct send_scratch);
} send_scratch SEC(".maps");

#define MUP_DUPLICATE_WINDOW_NS 2000000000ULL
/* A down path records the time of a reply at most this often. */
#define MUP_DOWN_SEEN_STEP_NS 1000000000ULL
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

/*
 * mup_count_client_path adds one data packet of bytes bytes to the client path
 * counter at index. The verifier checks this global function once, so a count
 * point adds no branch to the program that calls it.
 */
__attribute__((noinline)) int mup_count_client_path(__u32 index, __u32 bytes)
{
	struct path_counter_v1 *counter;

	if (index >= MUP_PATH_COUNTERS)
		return 0;
	counter = bpf_map_lookup_elem(&client_path_counters, &index);
	if (!counter)
		return 0;
	counter->packets += 1;
	counter->bytes += bytes;
	return 0;
}

/*
 * mup_count_server_path adds one data packet of bytes bytes to the counter of
 * one path of a client on the server, if Go created that counter. The key goes
 * into send_scratch, so the count takes no stack for it. A caller in a send
 * has no more use for the down path key there. The verifier checks this
 * global function once, so a count point adds no branch to the large server
 * programs.
 */
__attribute__((noinline)) int mup_count_server_path(__u32 advertised_ip,
						    __u64 instance_nonce,
						    __u32 path_id,
						    __u32 direction,
						    __u32 bytes)
{
	struct send_scratch_layout *scratch;
	struct path_counter_v1 *counter;
	__u32 scratch_key = 0;

	scratch = bpf_map_lookup_elem(&send_scratch, &scratch_key);
	if (!scratch)
		return 0;
	scratch->counter_key.client.advertised_ip = advertised_ip;
	scratch->counter_key.client.padding = 0;
	scratch->counter_key.client.instance_nonce = instance_nonce;
	scratch->counter_key.path_id = path_id;
	scratch->counter_key.direction = direction;
	counter = bpf_map_lookup_elem(&server_path_counters,
				      &scratch->counter_key);
	if (!counter)
		return 0;
	counter->packets += 1;
	counter->bytes += bytes;
	return 0;
}

/* The IPv4 total length of a parsed packet. */
static __always_inline __u32 mup_packet_length(const struct mup_packet *packet)
{
	return mup_read_be16((const __u8 *)&packet->ipv4->total_length);
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
	__u32 first_route = 1;
	__u32 *source_routes;
	long update_error;

	existing = bpf_map_lookup_elem(&client_peer_by_endpoint, endpoint);
	if (existing) {
		existing->last_seen_ns = now;
		*peer_token = existing->peer_token;
		return MUP_DROP_NONE;
	}

	source_routes = bpf_map_lookup_elem(&client_routes_by_source,
					    &endpoint->source_ip);
	if (source_routes && *source_routes >= MUP_MAX_ROUTES_PER_SOURCE)
		return MUP_DROP_SOURCE_LIMIT;

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

	if (source_routes) {
		__sync_fetch_and_add(source_routes, 1);
	} else if (bpf_map_update_elem(&client_routes_by_source,
				       &endpoint->source_ip, &first_route,
				       BPF_NOEXIST)) {
		source_routes = bpf_map_lookup_elem(&client_routes_by_source,
						    &endpoint->source_ip);
		if (source_routes)
			__sync_fetch_and_add(source_routes, 1);
	}

	*peer_token = allocated;
	return MUP_DROP_NONE;
}

static __always_inline __u32 mup_mask_has(__u32 mask, __u32 index)
{
	__u32 bit = (mask >> index) & 1;

	asm volatile("" : "+r"(bit));
	return bit;
}

static __always_inline __u32 mup_mask64_has(__u64 mask, __u32 index)
{
	__u64 bit = (mask >> (index & 63)) & 1;

	asm volatile("" : "+r"(bit));
	return bit;
}

/* A source range is set when first is not 0 and last is not below first. */
static __always_inline int mup_src_has(__u16 first, __u16 last)
{
	return first && last >= first;
}

static __always_inline int mup_src_contains(__u16 first, __u16 last,
					    __u16 value)
{
	return mup_src_has(first, last) && value >= first && value <= last;
}

/*
 * mup_src_random returns a random value from first to last of a set range.
 * mup_src_pick does the same, or returns fallback when the range is not set.
 * A caller picks once for each copy that it sends and gives the value to the
 * rewrite, so the checksum math of that copy sees one value.
 */
static __always_inline __u16 mup_src_random(__u16 first, __u16 last)
{
	return first + bpf_get_prandom_u32() % ((__u32)last - first + 1);
}

static __always_inline __u16 mup_src_pick(__u16 first, __u16 last,
					  __u16 fallback)
{
	if (!mup_src_has(first, last))
		return fallback;
	return mup_src_random(first, last);
}

/*
 * mup_icmp_tag returns the path tag in the Echo sequence of an ICMP packet,
 * or 0 for a UDP packet. A tag above MUP_MAX_PATH_TAG is not a path tag, for
 * example the 0xffff that a device writes when it completes a partial
 * checksum, so it counts as 0.
 */
static __always_inline __u32 mup_icmp_tag(const struct mup_packet *packet)
{
	const struct mup_icmphdr *icmp = packet->l4;
	__u32 tag;

	if (packet->transport != MUP_TRANSPORT_ICMP)
		return 0;
	tag = MUP_ICMP_SEQUENCE_TAG(mup_read_be16((const __u8 *)&icmp->sequence));
	return tag > MUP_MAX_PATH_TAG ? 0 : tag;
}

/*
 * mup_src_match checks the source port of a reply, or its ICMP identifier,
 * against one path of the client. src is the source range of the path, and
 * slot is its slot. A UDP reply of a path with a range comes from a port of
 * the range. A tagged ICMP reply has the tag of the slot and an identifier of
 * the range of the path. An untagged reply has the server port of the path.
 * A path with a range takes an untagged ICMP reply too, because a partial
 * reply of the server cannot carry the tag.
 */
static __always_inline int mup_src_match(const struct path_src_v1 *src,
					 __u16 server_port, __u16 observed,
					 __u8 transport, __u32 tag, __u32 slot)
{
	__u16 first = src ? src->first : 0;
	__u16 last = src ? src->last : 0;

	if (transport == MUP_TRANSPORT_ICMP && tag)
		return tag == slot + 1 && mup_src_contains(first, last, observed);
	if (transport == MUP_TRANSPORT_UDP && mup_src_has(first, last))
		return observed >= first && observed <= last;
	return observed == server_port;
}

/*
 * apply_up_reflect reflects the upstream of an up path through a member of its
 * pool, when the slot has an up_reflect_members entry. It picks a member by the
 * balance mode, and it rewrites a local copy of the path. On an ICMP path the
 * source becomes the server and the destination becomes the member, so the
 * member answers the server with an Echo Reply. On a UDP path the source
 * becomes the member and the destination stays the server. A slot without an
 * entry, or with no member, keeps the path as it is.
 */
static __always_inline void apply_up_reflect(__u32 index,
					     struct path_config_v1 *path,
					     __u32 peer_token)
{
	struct up_reflect_v1 *reflect;
	__u32 cursor_key = 0;
	__be32 member = 0;
	__be32 server;
	__u32 count;
	__u32 slot;

	reflect = bpf_map_lookup_elem(&up_reflect_members, &index);
	if (!reflect)
		return;
	count = reflect->count;
	if (count == 0 || count > MUP_MAX_POOL)
		return;
	if (reflect->flags & MUP_FLAG_BALANCE_PER_PACKET) {
		__u32 *cursor = bpf_map_lookup_elem(&up_reflect_cursor,
						    &cursor_key);

		if (!cursor)
			return;
		slot = (*cursor)++ % count;
	} else {
		__u32 hash = peer_token * 0x9e3779b1U;

		hash ^= hash >> 16;
		slot = hash % count;
	}
#pragma clang loop unroll(full)
	for (int member_index = 0; member_index < MUP_MAX_POOL; member_index++) {
		if ((__u32)member_index == slot)
			member = reflect->members[member_index];
	}
	if (!member)
		return;
	server = path->destination_ip;
	if (path->transport == MUP_TRANSPORT_ICMP) {
		path->source_ip = server;
		path->destination_ip = member;
	} else {
		path->source_ip = member;
	}
}

static __always_inline struct path_config_v1 *select_client_path(
	const struct path_group_v1 *group, __u32 peer_token,
	__u32 *selected_index_out)
{
	struct path_state_v1 *state;
	struct path_config_v1 *path;
	struct path_config_v1 *selected = 0;
	__u32 state_key = 0;
	__u32 selected_index = 0;
	__u32 healthy_count = 0;
	__u32 usable_mask;
	__u8 selected_priority = 0xff;

	if (selected_index_out)
		*selected_index_out = 0;
	state = bpf_map_lookup_elem(&path_state, &state_key);
	if (!state)
		return 0;
	usable_mask = state->healthy_mask & group->path_mask;
	if (!usable_mask)
		return 0;

	if (group->mode == MUP_MODE_BALANCER) {
#pragma clang loop unroll(full)
		for (int index = 0; index < 8; index++) {
			if (!mup_mask_has(usable_mask, index))
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
			if (!mup_mask_has(usable_mask, index))
				continue;
			__u32 key = index;
			path = bpf_map_lookup_elem(&path_config, &key);
			if (!path || !path->destination_ip || !path->ifindex)
				continue;
			if (healthy_count == ordinal) {
				if (selected_index_out)
					*selected_index_out = index;
				return path;
			}
			healthy_count++;
		}
		return 0;
	}

#pragma clang loop unroll(full)
	for (int index = 0; index < 8; index++) {
		if (!mup_mask_has(usable_mask, index))
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
	if (selected_index_out)
		*selected_index_out = selected_index;
	return bpf_map_lookup_elem(&path_config, &selected_index);
}

/* A prefix mask in network byte order. The BPF target is little-endian. */
static __always_inline __be32 mup_prefix_netmask(__u8 prefix)
{
	if (prefix == 0)
		return 0;
	if (prefix >= 32)
		return 0xffffffff;
	return __builtin_bswap32(0xffffffffU << (32 - prefix));
}

/*
 * A downstream packet must come from a path of the group of its peer: from
 * the server of the path, from the return IP of the path if it has one, or
 * from any address in the return pool of the path if it has a pool. Its port
 * must match the path as mup_src_match says, and tag is its path tag.
 */
static __always_inline int is_client_downstream_source(
	const struct mup_packet *packet, __u32 path_mask, __u32 tag)
{
	struct path_config_v1 *path;
	struct path_return_v1 *path_return;
	struct path_src_v1 *src;
	__be32 source = packet->ipv4->source;
	__be32 expected_ip;
	int matched;
	__u16 observed_port = packet->transport == MUP_TRANSPORT_UDP ?
				  packet->source_port : packet->server_port;

#pragma clang loop unroll(full)
	for (int index = 0; index < 8; index++) {
		if (!mup_mask_has(path_mask, index))
			continue;
		__u32 key = index;
		path = bpf_map_lookup_elem(&path_config, &key);
		path_return = bpf_map_lookup_elem(&path_returns, &key);
		if (!path || !path_return)
			continue;
		if (path_return->flags & MUP_FLAG_RETURN_POOL) {
			__be32 mask = mup_prefix_netmask(path_return->prefix);
			matched = (source & mask) ==
				  (path_return->return_ip & mask);
		} else {
			expected_ip = (path_return->flags & MUP_FLAG_RETURN_IP) ?
					      path_return->return_ip :
					      path->destination_ip;
			matched = expected_ip == source;
		}
		if (!matched || path->transport != packet->transport)
			continue;
		src = bpf_map_lookup_elem(&client_path_src, &key);
		if (mup_src_match(src, path->server_port, observed_port,
				  packet->transport, tag, index))
			return 1;
	}
	return 0;
}

/*
 * A group with separate down paths also accepts a reply from one of its down
 * paths: from the server address of a direct path, from the return IP of the
 * path, or from any address in its return pool. Its port must match the down
 * path as mup_src_match says, and tag is its path tag. The match records the
 * time, at most once a second, so mupctl can show which down paths carry data.
 * It also counts the packet on the egress path counter of the slot. The
 * caller passes no control frame here.
 */
static __always_inline int is_client_down_source(
	const struct mup_packet *packet, __u32 down_mask, __u32 tag)
{
	struct client_down_path_v1 *down;
	struct path_src_v1 *src;
	__be32 source = packet->ipv4->source;
	int matched;
	__u16 observed_port = packet->transport == MUP_TRANSPORT_UDP ?
				  packet->source_port : packet->server_port;

#pragma clang loop unroll(full)
	for (int index = 0; index < 8; index++) {
		if (!mup_mask_has(down_mask, index))
			continue;
		__u32 key = index;
		down = bpf_map_lookup_elem(&client_down_paths, &key);
		if (!down || !down->server_ip)
			continue;
		if (down->flags & MUP_FLAG_RETURN_POOL) {
			__be32 mask = mup_prefix_netmask(down->prefix);
			matched = (source & mask) == (down->return_ip & mask);
		} else if (down->flags & MUP_FLAG_RETURN_IP) {
			matched = down->return_ip == source;
		} else {
			matched = down->server_ip == source;
		}
		if (!matched || down->transport != packet->transport)
			continue;
		src = bpf_map_lookup_elem(&client_down_src, &key);
		if (mup_src_match(src, down->server_port, observed_port,
				  packet->transport, tag, index)) {
			__u64 now = bpf_ktime_get_ns();

			if (now - down->last_seen_ns > MUP_DOWN_SEEN_STEP_NS)
				down->last_seen_ns = now;
			mup_count_client_path(MUP_PATH_COUNTER_EGRESS_BASE + index,
					      mup_packet_length(packet));
			return 1;
		}
	}
	return 0;
}

/*
 * is_client_icmp_port reports an Echo Reply of a client path. An untagged
 * reply has the server port of an ICMP path or down path as its identifier.
 * A reply with tag T belongs to slot T - 1 only, so its check needs no loop:
 * the path or the down path of the slot must use ICMP and have a source range
 * that holds the identifier.
 */
static __always_inline int is_client_icmp_port(
	const struct mup_packet *packet, __u32 tag)
{
	struct path_config_v1 *path;
	struct client_down_path_v1 *down;
	struct path_src_v1 *src;

	if (tag) {
		__u32 key = (tag - 1) & 7;

		path = bpf_map_lookup_elem(&path_config, &key);
		src = bpf_map_lookup_elem(&client_path_src, &key);
		if (path && src && path->destination_ip &&
		    path->transport == MUP_TRANSPORT_ICMP &&
		    mup_src_contains(src->first, src->last, packet->server_port))
			return 1;
		down = bpf_map_lookup_elem(&client_down_paths, &key);
		src = bpf_map_lookup_elem(&client_down_src, &key);
		return down && src && down->server_ip &&
		       down->transport == MUP_TRANSPORT_ICMP &&
		       mup_src_contains(src->first, src->last,
					packet->server_port);
	}
#pragma clang loop unroll(full)
	for (int index = 0; index < 8; index++) {
		__u32 key = index;
		path = bpf_map_lookup_elem(&path_config, &key);
		if (path && path->destination_ip &&
		    path->transport == MUP_TRANSPORT_ICMP &&
		    path->server_port == packet->server_port)
			return 1;
		down = bpf_map_lookup_elem(&client_down_paths, &key);
		if (down && down->server_ip &&
		    down->transport == MUP_TRANSPORT_ICMP &&
		    down->server_port == packet->server_port)
			return 1;
	}
	return 0;
}

/*
 * A server with a downstream burst sends each reply on several down paths.
 * The client keeps the first copy of each message for 2 seconds and drops the
 * others, so each peer gets one copy. The key is the token and the first 24
 * WireGuard bytes, which hold the counter of a data message.
 */
static __always_inline int check_client_duplicate(
	const struct mup_packet *packet, __u32 peer_token)
{
	struct client_duplicate_key_v1 duplicate = {};
	__u64 now = bpf_ktime_get_ns();
	__u64 *seen;

	if (!mup_payload_fits(packet, sizeof(duplicate.identity)))
		return MUP_DROP_WG_LENGTH;
	duplicate.peer_token = peer_token;
#pragma clang loop unroll(full)
	for (int index = 0; index < sizeof(duplicate.identity); index++)
		duplicate.identity[index] = packet->payload[index];
	seen = bpf_map_lookup_elem(&client_duplicate_cache, &duplicate);
	if (seen && now >= *seen && now - *seen < MUP_DUPLICATE_WINDOW_NS)
		return MUP_DROP_DUPLICATE;
	if (bpf_map_update_elem(&client_duplicate_cache, &duplicate, &now, BPF_ANY))
		return MUP_DROP_MAP_INVARIANT;
	return MUP_DROP_NONE;
}

static __always_inline int redirect_packet(__u32 ifindex)
{
	if (!ifindex)
		return TC_ACT_SHOT;
	return bpf_redirect_neigh(ifindex, 0, 0, 0);
}

/*
 * mup_bridge_wrap puts a packet in the wrapper of a MUP bridge. It inserts 20
 * bytes after the IPv4 header for a UDP header and a bridge header, and turns
 * the IPv4 header into a UDP packet from local_ip to bridge_ip. Bits 0 to 15
 * of ports are the destination port, which picks the entry of the bridge.
 * Bits 16 to 31 are the source port, and 0 there means the destination port
 * at both ends. A BPF function has at most five arguments, so both ports
 * share one. The bridge header keeps the protocol and the addresses of the
 * packet. The transport header and the payload do not move, so the inner
 * checksum stays valid, and a partial checksum stays partial. Not every
 * device completes a partial checksum behind the wrapper, so the bridge
 * completes one that arrives incomplete. The outer UDP checksum is zero. A
 * wrapper that a reflector answers to the bridge goes from the bridge address
 * to the reflector, so its caller passes those two addresses as local_ip and
 * bridge_ip, and then calls mup_bridge_echo. The function returns
 * MUP_DROP_BRIDGE_SIZE without a change if the wrapped packet does not fit
 * the MTU of ifindex, and another drop reason if it fails after the change.
 * The verifier checks this global function once for all callers.
 */
__attribute__((noinline)) int mup_bridge_wrap(struct __sk_buff *skb,
					      __u32 local_ip, __u32 bridge_ip,
					      __u32 ports, __u32 ifindex)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct mup_iphdr *ipv4 = data + sizeof(struct ethhdr);
	__u8 *wrapper;
	__u32 mtu = 0;
	__be32 source;
	__be32 destination;
	__u16 total_length;
	__u8 protocol;

	if ((void *)(ipv4 + 1) > data_end)
		return MUP_DROP_MALFORMED_IPV4;
	source = ipv4->source;
	destination = ipv4->destination;
	protocol = ipv4->protocol;
	total_length = mup_read_be16((const __u8 *)&ipv4->total_length);
	if (total_length > 0xffff - MUP_BRIDGE_OVERHEAD)
		return MUP_DROP_BRIDGE_SIZE;
	if (bpf_check_mtu(skb, ifindex, &mtu, MUP_BRIDGE_OVERHEAD, 0))
		return MUP_DROP_BRIDGE_SIZE;
	if (bpf_skb_adjust_room(skb, MUP_BRIDGE_OVERHEAD, BPF_ADJ_ROOM_NET, 0))
		return MUP_DROP_BRIDGE_SIZE;
	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	ipv4 = data + sizeof(struct ethhdr);
	wrapper = (__u8 *)(ipv4 + 1);
	if (wrapper + MUP_BRIDGE_OVERHEAD > (__u8 *)data_end)
		return MUP_DROP_MAP_INVARIANT;
	ipv4->protocol = MUP_IPPROTO_UDP;
	ipv4->source = local_ip;
	ipv4->destination = bridge_ip;
	mup_write_be16(&ipv4->total_length, total_length + MUP_BRIDGE_OVERHEAD);
	mup_refresh_ipv4_checksum(ipv4);
	/* The outer UDP length is the old IPv4 total length. */
	mup_write_be16((__be16 *)wrapper, (ports >> 16) ? ports >> 16 : ports);
	mup_write_be16((__be16 *)(wrapper + 2), ports);
	mup_write_be16((__be16 *)(wrapper + 4), total_length);
	wrapper[6] = 0;
	wrapper[7] = 0;
	wrapper[8] = MUP_BRIDGE_MAGIC_0;
	wrapper[9] = MUP_BRIDGE_MAGIC_1;
	wrapper[10] = MUP_BRIDGE_VERSION;
	wrapper[11] = protocol;
	__builtin_memcpy(wrapper + 12, &source, sizeof(source));
	__builtin_memcpy(wrapper + 16, &destination, sizeof(destination));
	return MUP_DROP_NONE;
}

/*
 * mup_bridge_echo turns the UDP wrapper that mup_bridge_wrap just built into
 * an ICMP Echo Request, so a reflector answers it to the bridge. The UDP
 * destination port becomes the identifier, which picks the entry of the
 * bridge, and the UDP source port becomes the sequence. The bridge header
 * stays in place as the start of the Echo payload, so the overhead stays
 * MUP_BRIDGE_OVERHEAD. The reflector checks the ICMP checksum. The inner
 * packet is an ICMP message with a valid checksum, and its words sum to
 * 0xffff, which adds nothing in one's complement. So the checksum of the Echo
 * Request is the checksum of its 20 wrapper bytes alone. The inner packet does
 * not change, so mup_bridge_unwrap restores it. The verifier checks this
 * global function once for all callers.
 */
__attribute__((noinline)) int mup_bridge_echo(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct mup_iphdr *ipv4 = data + sizeof(struct ethhdr);
	__u8 *wrapper = (__u8 *)(ipv4 + 1);
	__u8 sequence_high;
	__u8 sequence_low;
	__u32 sum = 0;

	if (wrapper + MUP_BRIDGE_OVERHEAD > (__u8 *)data_end)
		return MUP_DROP_BRIDGE_PACKET;
	if (ipv4->protocol != MUP_IPPROTO_UDP)
		return MUP_DROP_BRIDGE_PACKET;
	sequence_high = wrapper[0];
	sequence_low = wrapper[1];
	wrapper[4] = wrapper[2];
	wrapper[5] = wrapper[3];
	wrapper[6] = sequence_high;
	wrapper[7] = sequence_low;
	wrapper[0] = MUP_ICMP_ECHO_REQUEST;
	wrapper[1] = 0;
	wrapper[2] = 0;
	wrapper[3] = 0;
#pragma clang loop unroll(full)
	for (int offset = 0; offset < MUP_BRIDGE_OVERHEAD; offset += 2)
		sum += mup_read_be16(wrapper + offset);
	mup_write_be16((__be16 *)(wrapper + 2), ~mup_csum_fold(sum));
	ipv4->protocol = MUP_IPPROTO_ICMP;
	mup_refresh_ipv4_checksum(ipv4);
	return MUP_DROP_NONE;
}

/*
 * mup_bridge_unwrap removes the wrapper of a MUP bridge, the UDP form or the
 * ICMP Echo form. It writes the protocol and the addresses of the bridge
 * header into the IPv4 header, and removes the 20 bytes after it. The caller
 * checks the wrapper first. The function returns a drop reason.
 */
__attribute__((noinline)) int mup_bridge_unwrap(struct __sk_buff *skb)
{
	void *data;
	void *data_end;
	struct mup_iphdr *ipv4;
	__u8 *wrapper;
	__u16 total_length;

	if (skb->len < sizeof(struct ethhdr) + sizeof(struct mup_iphdr) +
			       MUP_BRIDGE_OVERHEAD + 8 ||
	    bpf_skb_pull_data(skb, sizeof(struct ethhdr) +
					   sizeof(struct mup_iphdr) +
					   MUP_BRIDGE_OVERHEAD))
		return MUP_DROP_BRIDGE_PACKET;
	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	ipv4 = data + sizeof(struct ethhdr);
	wrapper = (__u8 *)(ipv4 + 1);
	if (wrapper + MUP_BRIDGE_OVERHEAD > (__u8 *)data_end)
		return MUP_DROP_BRIDGE_PACKET;
	total_length = mup_read_be16((const __u8 *)&ipv4->total_length);
	if (total_length < sizeof(*ipv4) + MUP_BRIDGE_OVERHEAD + 8)
		return MUP_DROP_BRIDGE_PACKET;
	ipv4->protocol = wrapper[11];
	__builtin_memcpy(&ipv4->source, wrapper + 12, sizeof(ipv4->source));
	__builtin_memcpy(&ipv4->destination, wrapper + 16,
			 sizeof(ipv4->destination));
	mup_write_be16(&ipv4->total_length, total_length - MUP_BRIDGE_OVERHEAD);
	mup_refresh_ipv4_checksum(ipv4);
	if (bpf_skb_adjust_room(skb, -MUP_BRIDGE_OVERHEAD, BPF_ADJ_ROOM_NET, 0))
		return MUP_DROP_BRIDGE_PACKET;
	return MUP_DROP_NONE;
}

/* MUP accepts no IPv4 options, so the payload offset is fixed. */
#define MUP_PAYLOAD_OFFSET \
	(sizeof(struct ethhdr) + sizeof(struct mup_iphdr) + 8)

/* A csum_partial sum in memory order, as big-endian 16-bit words. */
static __always_inline __u32 mup_wsum_be16(__u32 wsum)
{
	__u16 folded = mup_csum_fold(wsum);

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return (__u16)((folded >> 8) | (folded << 8));
#else
	return folded;
#endif
}

/*
 * mup_payload_sum_of returns the one's complement sum of the transport
 * payload of a packet without IPv4 options, as big-endian 16-bit words, or a
 * negative value. The payload can be in page fragments, so the function
 * copies it to a scratch buffer, chunk by chunk, and bpf_csum_diff sums each
 * chunk. The verifier checks this global function once for all callers.
 */
__attribute__((noinline)) int mup_payload_sum_of(struct __sk_buff *skb,
						  __u32 length)
{
	struct csum_scratch *scratch;
	__u32 offset = MUP_PAYLOAD_OFFSET;
	__u32 key = 0;
	__u32 tail = 0;
	__s64 wsum = 0;

	scratch = bpf_map_lookup_elem(&csum_scratch, &key);
	if (!scratch || length > MUP_CSUM_CHUNK * MUP_CSUM_CHUNKS)
		return -1;
	/* A bounded loop: the verifier walks each of its iterations. */
	for (int index = 0; index < MUP_CSUM_CHUNKS; index++) {
		if (length < MUP_CSUM_CHUNK)
			break;
		if (bpf_skb_load_bytes(skb, offset, scratch->bytes,
				       MUP_CSUM_CHUNK))
			return -1;
		wsum = bpf_csum_diff(0, 0, (__be32 *)scratch->bytes,
				     MUP_CSUM_CHUNK, (__u32)wsum);
		if (wsum < 0)
			return -1;
		offset += MUP_CSUM_CHUNK;
		length -= MUP_CSUM_CHUNK;
	}
	/* The rest is shorter than a chunk, so its bits give the parts. */
#pragma clang loop unroll(full)
	for (__u32 size = MUP_CSUM_CHUNK / 2; size >= 4; size /= 2) {
		if (!(length & size))
			continue;
		if (bpf_skb_load_bytes(skb, offset, scratch->bytes, size))
			return -1;
		wsum = bpf_csum_diff(0, 0, (__be32 *)scratch->bytes, size,
				     (__u32)wsum);
		if (wsum < 0)
			return -1;
		offset += size;
	}
	if (length & 2) {
		if (bpf_skb_load_bytes(skb, offset, scratch->bytes, 2))
			return -1;
		tail += mup_read_be16(scratch->bytes);
		offset += 2;
	}
	if (length & 1) {
		if (bpf_skb_load_bytes(skb, offset, scratch->bytes, 1))
			return -1;
		tail += (__u32)scratch->bytes[0] << 8;
	}
	return mup_wsum_be16((__u32)wsum) + tail;
}

/*
 * rewrite_icmp_partial rewrites a packet that still has CHECKSUM_PARTIAL
 * into ICMP, and computes the ICMP checksum itself. Some devices, for
 * example vmxnet3, do not complete the partial checksum of an ICMP packet,
 * and the packet then leaves with a checksum of zero. The sequence stays
 * zero. A device that completes the checksum writes the sum of a valid
 * message, 0 or 0xffff, into the sequence, and the checksum stays valid.
 */
static __always_inline int rewrite_icmp_partial(struct __sk_buff *skb,
						struct mup_packet *packet,
						__be32 source_ip,
						__be32 destination_ip,
						__u8 type, __u16 identifier,
						__u32 peer_token)
{
	int payload_sum;

	if (mup_rewrite_icmp_partial(packet, source_ip, destination_ip, type,
				     identifier, peer_token))
		return -1;
	payload_sum = mup_payload_sum_of(skb, packet->payload_length);
	if (payload_sum < 0)
		return -1;
	mup_finish_rewrite(packet, (__u32)payload_sum);
	return 0;
}

/*
 * complete_udp_checksum gives a UDP packet with a checksum of zero its
 * computed checksum, so that the rewrites can update it. IPv4 lets a sender
 * send zero for no checksum. Some NAT devices also write zero for a computed
 * checksum of zero, where RFC 768 says 0xffff, so about 1 packet in 65536
 * of their flows has it. MUP cannot derive a payload sum from zero, so it
 * computes the sum from the payload. A packet with another checksum, or an
 * ICMP packet, stays as it is.
 */
static __always_inline int complete_udp_checksum(struct __sk_buff *skb,
						 struct mup_packet *packet)
{
	int payload_sum;

	if (packet->transport != MUP_TRANSPORT_UDP || mup_l4_checksum(packet))
		return 0;
	payload_sum = mup_payload_sum_of(skb, packet->payload_length);
	if (payload_sum < 0)
		return -1;
	mup_write_l4_checksum(packet,
			      ~mup_csum_fold((__u32)payload_sum +
					     mup_l4_header_sum(packet)));
	return 0;
}

/*
 * A partial packet came from a local socket and still has CHECKSUM_PARTIAL.
 * A UDP rewrite leaves the checksum to the device, and an ICMP rewrite
 * computes it.
 *
 * A path slot with a source range sends each packet from a random value of
 * the range: the UDP source port instead of the listen port, or the ICMP
 * identifier instead of the server port. An ICMP packet then has the tag of
 * the slot in its sequence. A partial ICMP packet keeps the server port and
 * no tag, because a device that completes its checksum overwrites the
 * sequence, and the server finds such a packet by its exact key.
 */
static __always_inline int rewrite_for_path(
	struct __sk_buff *skb,
	struct mup_packet *packet,
	__u16 listen_port,
	const struct path_config_v1 *path,
	__u32 index,
	__u32 peer_token,
	int partial)
{
	struct path_src_v1 *src;
	__u32 key = index & 7;
	__u16 first = 0;
	__u16 last = 0;
	__u16 source_port;

	src = bpf_map_lookup_elem(&client_path_src, &key);
	if (src) {
		first = src->first;
		last = src->last;
	}
	if (path->transport == MUP_TRANSPORT_UDP) {
		source_port = mup_src_pick(first, last, listen_port);
		if (partial)
			return mup_rewrite_udp_partial(packet, path->source_ip,
						       path->destination_ip,
						       source_port,
						       path->server_port,
						       peer_token);
		return mup_rewrite_udp(packet, path->source_ip,
				       path->destination_ip,
				       source_port,
				       path->server_port);
	}
	if (path->transport == MUP_TRANSPORT_ICMP && partial)
		return rewrite_icmp_partial(skb, packet, path->source_ip,
					    path->destination_ip,
					    MUP_ICMP_ECHO_REQUEST,
					    path->server_port, peer_token);
	if (path->transport == MUP_TRANSPORT_ICMP) {
		__u16 identifier = path->server_port;
		__u32 sequence = peer_token;

		if (mup_src_has(first, last)) {
			identifier = mup_src_random(first, last);
			sequence = MUP_ICMP_SEQUENCE(key + 1, peer_token);
		}
		return mup_rewrite_icmp(packet, path->source_ip,
					path->destination_ip,
					MUP_ICMP_ECHO_REQUEST, identifier,
					(__u16)sequence);
	}
	return -2;
}

static __always_inline int prepare_clone_l2(
	struct __sk_buff *skb,
	const struct mup_packet *packet,
	__u32 expected_ifindex)
{
	struct send_scratch_layout *scratch;
	struct bpf_fib_lookup *fib;
	__u32 scratch_key = 0;

	scratch = bpf_map_lookup_elem(&send_scratch, &scratch_key);
	if (!scratch)
		return MUP_DROP_MAP_INVARIANT;
	fib = &scratch->fib;
	__builtin_memset(fib, 0, sizeof(*fib));
	fib->family = AF_INET;
	fib->l4_protocol = packet->ipv4->protocol;
	fib->tot_len = mup_read_be16((const __u8 *)&packet->ipv4->total_length);
	fib->ifindex = expected_ifindex;
	fib->tos = packet->ipv4->tos;
	fib->ipv4_src = packet->ipv4->source;
	fib->ipv4_dst = packet->ipv4->destination;
	if (packet->transport == MUP_TRANSPORT_UDP) {
		struct mup_udphdr *udp = packet->l4;

		fib->sport = udp->source;
		fib->dport = udp->destination;
	}
	if (bpf_fib_lookup(skb, fib, sizeof(*fib),
			   BPF_FIB_LOOKUP_OUTPUT) != BPF_FIB_LKUP_RET_SUCCESS)
		return MUP_DROP_FIB;
	if (fib->ifindex != expected_ifindex)
		return MUP_DROP_FIB;

#pragma clang loop unroll(full)
	for (int index = 0; index < 6; index++) {
		packet->ethernet->source[index] = fib->smac[index];
		packet->ethernet->destination[index] = fib->dmac[index];
	}
	return MUP_DROP_NONE;
}

#define MUP_BURST_SENT 0
#define MUP_BURST_SKIPPED 1
#define MUP_BURST_FAILED 2

__attribute__((noinline)) int mup_burst_clone(struct __sk_buff *skb, __u32 index,
					      __u32 listen_port, __u32 peer_token,
					      __u32 partial)
{
	struct mup_packet packet = {};
	struct path_config_v1 *mapped_path;
	struct path_config_v1 path = {};
	int result;

	if (index >= 8)
		return MUP_BURST_SKIPPED;
	if (parse_ipv4_l4(skb, &packet) != MUP_DROP_NONE)
		return MUP_BURST_FAILED;
	mapped_path = bpf_map_lookup_elem(&path_config, &index);
	if (!mapped_path || !mapped_path->destination_ip ||
	    !mapped_path->ifindex || mapped_path->transport > MUP_TRANSPORT_ICMP)
		return MUP_BURST_SKIPPED;
	path = *mapped_path;
	apply_up_reflect(index, &path, peer_token);
	result = rewrite_for_path(skb, &packet, (__u16)listen_port, &path,
				  index, peer_token, partial);
	if (result) {
		count_reason(result == -2 ? MUP_DROP_TRANSPORT : MUP_DROP_CHECKSUM);
		return MUP_BURST_FAILED;
	}
	/*
	 * The rewrite succeeded, so the copy counts on its path. A copy that the
	 * FIB or the neighbor then refuses counts too, so the measurement shows
	 * it as loss of the path.
	 */
	mup_count_client_path(index, mup_packet_length(&packet));
	result = prepare_clone_l2(skb, &packet, path.ifindex);
	if (result != MUP_DROP_NONE) {
		count_reason(result);
		return MUP_BURST_SKIPPED;
	}
	if (bpf_clone_redirect(skb, path.ifindex, 0)) {
		count_reason(MUP_DROP_NEIGHBOR);
		return MUP_BURST_SKIPPED;
	}
	return MUP_BURST_SENT;
}

static __always_inline int burst_client_packet(
	struct __sk_buff *skb,
	struct mup_packet *packet,
	__u16 listen_port,
	__u32 path_mask,
	__u32 peer_token,
	int partial)
{
	struct path_state_v1 *state;
	struct path_config_v1 *mapped_path;
	struct path_config_v1 path = {};
	__u32 state_key = 0;
	__u32 final_key;
	__u32 healthy_mask;
	int final_index = -1;
	int cloned = 0;
	int result;

	state = bpf_map_lookup_elem(&path_state, &state_key);
	if (!state)
		return count_and_drop(skb, MUP_DROP_NO_PATH);
	healthy_mask = state->healthy_mask & path_mask;
	if (!healthy_mask)
		return count_and_drop(skb, MUP_DROP_NO_PATH);

#pragma clang loop unroll(full)
	for (int index = 0; index < 8; index++) {
		__u32 key = index;

		if (!mup_mask_has(healthy_mask, index))
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
		if (!mup_mask_has(healthy_mask, index) || index == final_index)
			continue;
		result = mup_burst_clone(skb, index, listen_port, peer_token,
					 partial);
		if (result == MUP_BURST_FAILED)
			return TC_ACT_SHOT;
		if (result == MUP_BURST_SENT)
			cloned = 1;
	}

	*packet = (struct mup_packet){};
	result = parse_ipv4_l4(skb, packet);
	if (result != MUP_DROP_NONE)
		return cloned ? TC_ACT_SHOT : count_and_drop(skb, result);
	final_key = final_index;
	mapped_path = bpf_map_lookup_elem(&path_config, &final_key);
	if (!mapped_path || !mapped_path->destination_ip ||
	    !mapped_path->ifindex || mapped_path->transport > MUP_TRANSPORT_ICMP)
		return cloned ? TC_ACT_SHOT : count_and_drop(skb, MUP_DROP_NO_PATH);
	path = *mapped_path;
	apply_up_reflect(final_key, &path, peer_token);
	result = rewrite_for_path(skb, packet, listen_port, &path, final_key,
				  peer_token, partial);
	if (result == -2)
		return count_and_drop(skb, MUP_DROP_TRANSPORT);
	if (result)
		return count_and_drop(skb, MUP_DROP_CHECKSUM);
	mup_count_client_path(final_key, mup_packet_length(packet));
	return redirect_packet(path.ifindex);
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
	       left->ifindex == right->ifindex &&
	       left->listen_port == right->listen_port &&
	       left->src_first == right->src_first &&
	       left->src_last == right->src_last;
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
	__u16 reserved_port,
	__u16 *target_port)
{
	struct server_route_value_v1 *existing;
	struct server_reverse_value_v1 reverse = {};
	__u64 now = bpf_ktime_get_ns();
	__u16 allocated = 0;
	__u16 next = 0;
	long update_error;

	existing = bpf_map_lookup_elem(&server_route_by_key, route_key);
	if (existing) {
		*target_port = existing->target_port;
		refresh_server_route(existing, route_key, observed, now);
		return MUP_DROP_NONE;
	}

	if (bpf_map_pop_elem(&free_target_ports, &allocated))
		return MUP_DROP_TARGET_PORT_POOL;
	if (reserved_port && allocated == reserved_port) {
		if (bpf_map_pop_elem(&free_target_ports, &next)) {
			bpf_map_push_elem(&free_target_ports, &allocated, BPF_ANY);
			return MUP_DROP_TARGET_PORT_POOL;
		}
		bpf_map_push_elem(&free_target_ports, &allocated, BPF_ANY);
		allocated = next;
	}
	if (allocated == 0) {
		bpf_map_push_elem(&free_target_ports, &allocated, BPF_ANY);
		return MUP_DROP_MAP_INVARIANT;
	}

	/* The reverse entry holds the new route, so the stack keeps one copy. */
	reverse.route_value = *observed;
	reverse.route_value.target_port = allocated;
	reverse.route_value.last_seen_ns = now;
	update_error = bpf_map_update_elem(&server_route_by_key, route_key,
					   &reverse.route_value, BPF_NOEXIST);
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
	__u32 tag = 0;
	int partial;
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
			if (icmp->type != MUP_ICMP_ECHO_REPLY || icmp->code != 0)
				return MUP_TCX_NEXT;
			/*
			 * The token is in the WireGuard bytes, so the client
			 * reads only the tag of the sequence.
			 */
			tag = mup_icmp_tag(&packet);
			if (!is_client_icmp_port(&packet, tag))
				return MUP_TCX_NEXT;
		}
		result = validate_wg(&packet, 1, &peer_token);
		if (result != MUP_DROP_NONE) {
			if (packet.transport == MUP_TRANSPORT_ICMP)
				return MUP_TCX_NEXT;
			return count_and_drop(skb, result);
		}
		reverse = bpf_map_lookup_elem(&client_endpoint_by_token, &peer_token);
		if (!reverse)
			return count_and_drop(skb, MUP_DROP_ROUTE_MISS);
		/*
		 * The group of the peer decides which sources can answer it. A
		 * group with egress paths gets every reply on them, so the egress
		 * paths come first, and a reply from a source that an ingress
		 * path shares still counts on its egress path.
		 */
		group = bpf_map_lookup_elem(&path_groups,
					    &reverse->endpoint.listen_port);
		if (!group)
			return count_and_drop(skb, MUP_DROP_DOWNSTREAM_SOURCE);
		if (!is_client_down_source(&packet, group->down_mask, tag) &&
		    !is_client_downstream_source(&packet, group->path_mask, tag))
			return count_and_drop(skb, MUP_DROP_DOWNSTREAM_SOURCE);
		if (group->flags & MUP_GROUP_FLAG_DEDUP) {
			result = check_client_duplicate(&packet, peer_token);
			if (result != MUP_DROP_NONE)
				return count_and_drop(skb, result);
		}
		reverse->last_seen_ns = bpf_ktime_get_ns();
		forward = bpf_map_lookup_elem(&client_peer_by_endpoint,
					      &reverse->endpoint);
		if (!forward || forward->peer_token != peer_token)
			return count_and_drop(skb, MUP_DROP_MAP_INVARIANT);
		forward->last_seen_ns = reverse->last_seen_ns;
		if (complete_udp_checksum(skb, &packet) ||
		    mup_clear_peer_token(&packet) ||
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
	/* Only a packet on loopback can still have CHECKSUM_PARTIAL here. */
	partial = skb->ifindex == MUP_LOOPBACK_IFINDEX &&
		  mup_udp_is_partial(&packet);
	/* A partial checksum is never zero, so this keeps a partial packet. */
	if (complete_udp_checksum(skb, &packet))
		return count_and_drop(skb, MUP_DROP_CHECKSUM);

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
					   group->path_mask, peer_token,
					   partial);
	}
	__u32 selected_index = 0;
	path = select_client_path(group, peer_token, &selected_index);
	if (!path)
		return count_and_drop(skb, MUP_DROP_NO_PATH);
	struct path_config_v1 selected_path = *path;
	/*
	 * A bridge reflect route wraps the reflected packet for its bridge, so
	 * the bridge emits the spoofed packet that the client cannot send. The
	 * source and the port come from before the reflect, which is the
	 * advertised source and the server port the bridge takes.
	 */
	__be32 reflect_bridge = selected_path.bridge;
	__be32 reflect_source = selected_path.source_ip;
	__u16 reflect_port = selected_path.server_port;
	apply_up_reflect(selected_index, &selected_path, peer_token);
	if (mup_set_peer_token(&packet, peer_token))
		return count_and_drop(skb, MUP_DROP_MAP_INVARIANT);
	result = rewrite_for_path(skb, &packet, endpoint.listen_port,
				  &selected_path, selected_index, peer_token,
				  partial);
	if (result == -2)
		return count_and_drop(skb, MUP_DROP_TRANSPORT);
	if (result)
		return count_and_drop(skb, MUP_DROP_CHECKSUM);
	/* The wrapper of a bridge adds MUP_BRIDGE_OVERHEAD to the length. */
	__u32 sent_length = mup_packet_length(&packet);
	if (reflect_bridge) {
		int wrap = mup_bridge_wrap(skb, reflect_source, reflect_bridge,
					   reflect_port, selected_path.ifindex);
		if (wrap != MUP_DROP_NONE)
			return count_and_drop(skb, wrap);
		sent_length += MUP_BRIDGE_OVERHEAD;
	}
	mup_count_client_path(selected_index, sent_length);

	return redirect_packet(selected_path.ifindex);
}

/*
 * pick_reflector chooses one healthy address from the pool with base base and
 * transport transport.
 * The per-peer mode hashes the peer token to a slot, and the per-packet mode
 * steps a per-CPU cursor. Both start at a slot and walk to the next healthy
 * slot. It returns 0 when the pool is missing or has no healthy address.
 */
__attribute__((noinline)) __be32 pick_reflector(__be32 base, __u8 transport,
						__u8 flags, __u32 peer_token)
{
	struct reflector_key_v1 key = {};
	struct reflector_pool_v1 *pool;
	__u32 cursor_key = 0;
	__u32 count;
	__u32 slot;
	__u32 min_dist;

	key.base = base;
	key.transport = transport;
	pool = bpf_map_lookup_elem(&reflector_pools, &key);
	if (!pool)
		return 0;
	count = pool->count;
	if (count == 0 || count > MUP_MAX_POOL)
		return 0;
	if (flags & MUP_FLAG_BALANCE_PER_PACKET) {
		__u32 *cursor = bpf_map_lookup_elem(&reflector_cursor,
						    &cursor_key);
		if (!cursor)
			return 0;
		slot = (*cursor)++ % count;
	} else {
		__u32 hash = peer_token * 0x9e3779b1U;
		hash ^= hash >> 16;
		slot = hash % count;
	}
	/*
	 * Pick the healthy reflector at slot, or the next healthy one after it.
	 * The loop is unrolled so the array index is a compile-time constant, and
	 * mup_mask64_has hides the healthy bit from the verifier. Both keep the
	 * verifier cost low. The distance from slot avoids a modulo by a runtime
	 * count.
	 */
	min_dist = count;
	__be32 chosen = 0;
#pragma clang loop unroll(full)
	for (int index = 0; index < MUP_MAX_POOL; index++) {
		__u32 dist;

		if ((__u32)index >= count || !mup_mask64_has(pool->healthy_mask, index))
			continue;
		dist = (__u32)index >= slot ? (__u32)index - slot :
					      (__u32)index + count - slot;
		if (dist < min_dist) {
			min_dist = dist;
			chosen = pool->addresses[index];
		}
	}
	return chosen;
}

/*
 * The meta argument of mup_down_send packs the listen port in bits 0 to 15,
 * the down path ID in bits 16 to 18, the flags below, and the peer token in
 * bits 22 to 33. A BPF function has at most five arguments.
 */
#define MUP_DOWN_META_PARTIAL (1ULL << 19)
#define MUP_DOWN_META_CLONE (1ULL << 20)
#define MUP_DOWN_META_EGRESS (1ULL << 21)
#define MUP_DOWN_META_TOKEN_SHIFT 22

/*
 * down_send_core rewrites a reply of the target for one down path of a client
 * and sends it. A direct path sends from the server address of the path. A
 * path with a return IP or a pool reflects the reply as the other modes do.
 * With MUP_DOWN_META_CLONE, it sends a copy, returns one of the MUP_BURST_*
 * values, and the caller keeps the packet. Otherwise it returns the verdict.
 *
 * A partial reply on an ICMP path needs the sum of its payload. The caller
 * computes it once in payload_sum, because a call from here to
 * mup_payload_sum_of makes the stack of the server program too deep. It is
 * the sum of the payload before the peer token, whose reserved bytes are
 * zero, so the rewrite adds the token to it. The
 * function parses the packet again into packet, because a clone invalidates
 * the packet pointers.
 */
static __always_inline int down_send_core(struct __sk_buff *skb,
					  struct mup_packet *packet,
					  __u32 advertised_ip,
					  __u64 instance_nonce, __u64 meta,
					  __u32 payload_sum)
{
	struct send_scratch_layout *scratch;
	struct down_path_v1 *mapped;
	__u32 clone = (meta & MUP_DOWN_META_CLONE) != 0;
	__u32 partial = (meta & MUP_DOWN_META_PARTIAL) != 0;
	__u32 peer_token = (meta >> MUP_DOWN_META_TOKEN_SHIFT) & MUP_MAX_PEER_TOKEN;
	__u16 listen_port = meta & 0xffff;
	__u32 cursor_key = 0;
	__be32 member = 0;
	__be32 via_member = 0;
	__be32 source_ip;
	__be32 destination_ip;
	__u32 reason = MUP_DROP_NONE;
	__u32 ifindex;
	__u32 count;
	__u32 slot;
	__u16 server_port;
	__u16 source_port;
	__u8 transport;
	__u8 flags;
	__u8 type;
	int result;

	*packet = (struct mup_packet){};
	if (parse_ipv4_l4(skb, packet) != MUP_DROP_NONE)
		return clone ? MUP_BURST_FAILED : TC_ACT_SHOT;
	scratch = bpf_map_lookup_elem(&send_scratch, &cursor_key);
	if (!scratch) {
		reason = MUP_DROP_MAP_INVARIANT;
		goto fail;
	}
	__builtin_memset(&scratch->key, 0, sizeof(scratch->key));
	scratch->key.client.advertised_ip = advertised_ip;
	scratch->key.client.instance_nonce = instance_nonce;
	scratch->key.path_id = (meta >> 16) & 7;
	mapped = bpf_map_lookup_elem(&server_down_paths, &scratch->key);
	if (!mapped || !mapped->server_ip || !mapped->ifindex) {
		reason = MUP_DROP_NO_PATH;
		goto fail;
	}
	flags = mapped->flags;
	transport = mapped->transport;
	server_port = mapped->server_port;
	ifindex = mapped->ifindex;
	/*
	 * A path with a source range sends each reply from a random value of
	 * the range, and an ICMP reply has the tag of the down path. The wrapper
	 * of a bridge path takes the same value as its source port. A partial
	 * ICMP reply keeps the server port and no tag, because a device that
	 * completes its checksum overwrites the sequence.
	 */
	source_port = server_port;
	if (mup_src_has(mapped->src_first, mapped->src_last))
		source_port = mup_src_random(mapped->src_first, mapped->src_last);
	if (flags & MUP_FLAG_RETURN_POOL) {
		count = mapped->count;
		if (count == 0 || count > MUP_MAX_POOL) {
			reason = MUP_DROP_NO_PATH;
			goto fail;
		}
		if (flags & MUP_FLAG_BALANCE_PER_PACKET) {
			__u32 *cursor = bpf_map_lookup_elem(&reflector_cursor,
							    &cursor_key);

			if (!cursor) {
				reason = MUP_DROP_MAP_INVARIANT;
				goto fail;
			}
			slot = (*cursor)++ % count;
		} else {
			__u32 hash = peer_token * 0x9e3779b1U;

			hash ^= hash >> 16;
			slot = hash % count;
		}
#pragma clang loop unroll(full)
		for (int index = 0; index < MUP_MAX_POOL; index++) {
			if ((__u32)index == slot)
				member = mapped->members[index];
		}
		if (!member) {
			reason = MUP_DROP_NO_PATH;
			goto fail;
		}
	} else if (flags & MUP_FLAG_RETURN_IP) {
		member = mapped->return_ip;
	}
	/*
	 * A bridge path with MUP_FLAG_BRIDGE_VIA builds the direct reply from
	 * the bridge address and applies the member to the wrapper instead.
	 */
	if ((flags & MUP_FLAG_BRIDGE_VIA) && member) {
		via_member = member;
		member = 0;
	}

	if (transport == MUP_TRANSPORT_UDP) {
		source_ip = member ? member : mapped->server_ip;
		if (partial)
			result = mup_rewrite_udp_partial(packet, source_ip,
							 advertised_ip,
							 source_port,
							 listen_port,
							 peer_token);
		else
			result = mup_rewrite_udp(packet, source_ip,
						 advertised_ip, source_port,
						 listen_port);
	} else if (transport == MUP_TRANSPORT_ICMP) {
		if (member) {
			source_ip = advertised_ip;
			destination_ip = member;
			type = MUP_ICMP_ECHO_REQUEST;
		} else {
			source_ip = mapped->server_ip;
			destination_ip = advertised_ip;
			type = MUP_ICMP_ECHO_REPLY;
		}
		if (partial) {
			result = mup_rewrite_icmp_partial(packet, source_ip,
							  destination_ip, type,
							  server_port,
							  peer_token);
			/*
			 * The token is at most MUP_MAX_PEER_TOKEN and fills
			 * payload bytes 2 and 3, so it is exactly one
			 * big-endian word of the sum.
			 */
			if (!result)
				mup_finish_rewrite(packet, payload_sum + peer_token);
		} else {
			__u32 sequence = peer_token;

			if (mup_src_has(mapped->src_first, mapped->src_last))
				sequence = MUP_ICMP_SEQUENCE(
					((meta >> 16) & 7) + 1, peer_token);
			result = mup_rewrite_icmp(packet, source_ip,
						  destination_ip, type,
						  source_port,
						  (__u16)sequence);
		}
	} else {
		reason = MUP_DROP_TRANSPORT;
		goto fail;
	}
	if (result) {
		/* A packet that failed half way cannot go on. */
		if (clone) {
			count_reason(MUP_DROP_CHECKSUM);
			return MUP_BURST_FAILED;
		}
		return count_and_drop(skb, MUP_DROP_CHECKSUM);
	}
	/*
	 * A path through a bridge wraps the reply for the bridge. The wrapper
	 * of a plain bridge path leaves from the local address. A UDP bridge
	 * via path forges the wrapper from the member. An ICMP bridge via path
	 * reflects it: the wrapper is an Echo Request from the bridge address
	 * to the member, and the Echo Reply of the member reaches the bridge.
	 * A copy of a burst loses the wrapper again after the clone, so the
	 * next path gets the reply as it was.
	 */
	if (flags & MUP_FLAG_BRIDGE) {
		__be32 wrap_source = mapped->local_ip;
		__be32 wrap_destination = mapped->server_ip;
		__u32 echo = via_member && transport == MUP_TRANSPORT_ICMP;

		if (echo) {
			wrap_source = mapped->server_ip;
			wrap_destination = via_member;
		} else if (via_member) {
			wrap_source = via_member;
		}
		reason = mup_bridge_wrap(skb, wrap_source, wrap_destination,
					 ((__u32)source_port << 16) | server_port,
					 ifindex);
		if (reason == MUP_DROP_BRIDGE_SIZE)
			goto fail;
		if (reason == MUP_DROP_NONE && echo)
			reason = mup_bridge_echo(skb);
		*packet = (struct mup_packet){};
		if (reason != MUP_DROP_NONE ||
		    parse_ipv4_l4(skb, packet) != MUP_DROP_NONE) {
			if (clone) {
				count_reason(MUP_DROP_BRIDGE_PACKET);
				return MUP_BURST_FAILED;
			}
			return count_and_drop(skb, MUP_DROP_BRIDGE_PACKET);
		}
	}
	/*
	 * The rewrite and the wrap succeeded, so the copy counts on its egress
	 * path, with the outer length of a bridge path. A copy that the FIB or
	 * the neighbor then refuses counts too, so the measurement shows it as
	 * loss of the path.
	 */
	mup_count_server_path(advertised_ip, instance_nonce, (meta >> 16) & 7,
			      MUP_PATH_COUNTER_EGRESS, mup_packet_length(packet));

	if (clone) {
		int sent = MUP_BURST_SENT;

		result = prepare_clone_l2(skb, packet, ifindex);
		if (result != MUP_DROP_NONE) {
			count_reason(result);
			sent = MUP_BURST_SKIPPED;
		} else if (bpf_clone_redirect(skb, ifindex, 0)) {
			count_reason(MUP_DROP_NEIGHBOR);
			sent = MUP_BURST_SKIPPED;
		}
		if ((flags & MUP_FLAG_BRIDGE) &&
		    mup_bridge_unwrap(skb) != MUP_DROP_NONE) {
			count_reason(MUP_DROP_BRIDGE_PACKET);
			return MUP_BURST_FAILED;
		}
		return sent;
	}
	if ((meta & MUP_DOWN_META_EGRESS) && ifindex == skb->ifindex &&
	    prepare_clone_l2(skb, packet, ifindex) == MUP_DROP_NONE)
		return TC_ACT_OK;
	return redirect_packet(ifindex);

fail:
	if (clone) {
		count_reason(reason);
		return MUP_BURST_SKIPPED;
	}
	return count_and_drop(skb, reason);
}

/*
 * mup_down_send is down_send_core in a function of its own, for the egress
 * program. The verifier checks it once, so the burst loop stays cheap. The
 * ingress program has a larger stack, so it runs the core inline.
 */
__attribute__((noinline)) int mup_down_send(struct __sk_buff *skb,
					    __u32 advertised_ip,
					    __u64 instance_nonce, __u64 meta,
					    __u32 payload_sum)
{
	struct mup_packet packet = {};

	return down_send_core(skb, &packet, advertised_ip, instance_nonce,
			      meta, payload_sum);
}

/*
 * send_down_reply picks the down paths of a reply with the downstream mode of
 * the client, among its healthy down paths. Fallback takes the lowest down
 * path ID, balancer hashes the token as the client upstream does, and burst
 * sends a copy on each healthy down path. The packet itself goes on the
 * highest path that it uses. With inline_send, the sends run inline and reuse
 * packet. Otherwise they call mup_down_send.
 */
static __always_inline int send_down_reply(
	struct __sk_buff *skb,
	struct mup_packet *packet,
	const struct server_reverse_value_v1 *reverse,
	const struct down_group_v1 *down,
	__u16 listen_port,
	int partial,
	int at_egress,
	int inline_send)
{
	__u32 usable = (__u32)down->path_mask & (__u32)down->healthy_mask;
	__u32 peer_token = reverse->route_key.peer_token;
	__u32 advertised_ip = reverse->route_key.client.advertised_ip;
	__u64 instance_nonce = reverse->route_key.client.instance_nonce;
	__u64 meta = listen_port;
	__u32 sending = 0;
	__u32 count = 0;
	__u32 ordinal;
	__u32 hash;
	__u32 final = 0;
	int payload_sum = 0;
	int result;

	if (partial)
		meta |= MUP_DOWN_META_PARTIAL;
	if (at_egress)
		meta |= MUP_DOWN_META_EGRESS;
	meta |= (__u64)(peer_token & MUP_MAX_PEER_TOKEN) << MUP_DOWN_META_TOKEN_SHIFT;
	if (!usable)
		return count_and_drop(skb, MUP_DROP_NO_PATH);

	if (down->mode == MUP_MODE_BURST) {
		sending = usable;
	} else if (down->mode == MUP_MODE_BALANCER) {
#pragma clang loop unroll(full)
		for (int index = 0; index < 8; index++) {
			if (mup_mask_has(usable, index))
				count++;
		}
		hash = peer_token * 0x9e3779b1U ^ usable * 0x85ebca6bU;
		hash ^= hash >> 16;
		ordinal = hash % count;
		count = 0;
#pragma clang loop unroll(full)
		for (int index = 0; index < 8; index++) {
			if (!mup_mask_has(usable, index))
				continue;
			if (count == ordinal)
				sending = 1U << index;
			count++;
		}
	} else {
		sending = usable & -usable;
	}
	if (!sending)
		return count_and_drop(skb, MUP_DROP_NO_PATH);
	/*
	 * Each copy has the same payload, so one sum serves them all. The sum
	 * is taken before the token is written, and down_send_core adds it.
	 */
	if (partial && (sending & down->icmp_mask)) {
		payload_sum = mup_payload_sum_of(skb, packet->payload_length);
		if (payload_sum < 0)
			return count_and_drop(skb, MUP_DROP_CHECKSUM);
	}
#pragma clang loop unroll(full)
	for (int index = 0; index < 8; index++) {
		if (mup_mask_has(sending, index))
			final = index;
	}
	/* A bounded loop keeps one copy of an inline send in the program. */
#pragma clang loop unroll(disable)
	for (__u32 index = 0; index < 8; index++) {
		__u64 clone_meta = meta | MUP_DOWN_META_CLONE | ((__u64)index << 16);

		if (!((sending >> index) & 1) || index == final)
			continue;
		if (inline_send)
			result = down_send_core(skb, packet, advertised_ip,
						instance_nonce, clone_meta,
						payload_sum);
		else
			result = mup_down_send(skb, advertised_ip,
					       instance_nonce, clone_meta,
					       payload_sum);
		if (result == MUP_BURST_FAILED)
			return TC_ACT_SHOT;
	}
	meta |= (__u64)(final & 7) << 16;
	if (inline_send)
		return down_send_core(skb, packet, advertised_ip,
				      instance_nonce, meta, payload_sum);
	return mup_down_send(skb, advertised_ip, instance_nonce, meta,
			     payload_sum);
}

/*
 * server_target_reply sends one reply of the target back to the client on the
 * return path of its route. A partial packet still has CHECKSUM_PARTIAL, so the
 * rewrite leaves the checksum to the device. At egress, a reply that leaves on
 * the same interface gets its Ethernet header from a FIB lookup and goes on,
 * so it does not pass the egress programs of the interface a second time.
 */
static __always_inline int server_target_reply(
	struct __sk_buff *skb,
	struct mup_packet *packet,
	struct server_reverse_value_v1 *reverse,
	int partial,
	int at_egress)
{
	struct registration_value_v1 *registration;
	struct server_route_value_v1 *forward;
	struct down_group_key_v1 down_key = {};
	struct down_group_v1 *down;
	__u16 listen_port = reverse->route_value.listen_port;
	__u32 peer_token = 0;
	__be32 pool_addr = 0;
	__u16 source_port;
	__u64 now;
	int result;

	result = validate_wg(packet, 0, &peer_token);
	if (result != MUP_DROP_NONE)
		return count_and_drop(skb, result);
	now = bpf_ktime_get_ns();
	registration = bpf_map_lookup_elem(&registration_by_key,
					   &reverse->route_key.client);
	if (!registration || registration->expires_at_ns < now)
		return count_and_drop(skb, MUP_DROP_NOT_REGISTERED);
	reverse->route_value.last_seen_ns = now;
	forward = bpf_map_lookup_elem(&server_route_by_key, &reverse->route_key);
	if (!forward || forward->target_port != packet->destination_port)
		return count_and_drop(skb, MUP_DROP_MAP_INVARIANT);
	forward->last_seen_ns = now;
	if (!partial && complete_udp_checksum(skb, packet))
		return count_and_drop(skb, MUP_DROP_CHECKSUM);
	if (!partial &&
	    mup_set_peer_token(packet, reverse->route_key.peer_token))
		return count_and_drop(skb, MUP_DROP_MAP_INVARIANT);
	/*
	 * A group with separate down paths lets the server pick the down path
	 * of each reply. The route knows the listen port of its group, so each
	 * group of a client gets its own down group. Other groups get the reply
	 * on the path of the latest upstream packet.
	 */
	down_key.client = reverse->route_key.client;
	down_key.listen_port = listen_port;
	down = bpf_map_lookup_elem(&server_down_groups, &down_key);
	if (down && down->path_mask)
		return send_down_reply(skb, packet, reverse, down, listen_port,
				       partial, at_egress, !at_egress);
	/*
	 * An ingress reflect path carries no reply reflection. Without a down
	 * group the server has no path to the client. A direct reply from the
	 * server address would be dropped by the client, and it would show a
	 * direct flow from the server to the client.
	 */
	if (reverse->route_value.flags & MUP_FLAG_UP_REFLECT)
		return count_and_drop(skb, MUP_DROP_NO_PATH);
	if (reverse->route_value.flags & MUP_FLAG_RETURN_POOL) {
		pool_addr = pick_reflector(reverse->route_value.return_ip,
					   reverse->route_value.transport,
					   reverse->route_value.flags,
					   reverse->route_key.peer_token);
		if (!pool_addr)
			return count_and_drop(skb, MUP_DROP_NO_PATH);
	}
	/*
	 * A route of a path with a source range sends each reply from a random
	 * value of the range, and an ICMP reply has the tag of the path of the
	 * route. A partial ICMP reply keeps the server port and no tag, because
	 * a device that completes its checksum overwrites the sequence.
	 */
	source_port = reverse->route_value.server_port;
	if (mup_src_has(reverse->route_value.src_first,
			reverse->route_value.src_last))
		source_port = mup_src_random(reverse->route_value.src_first,
					     reverse->route_value.src_last);
	if (reverse->route_value.transport == MUP_TRANSPORT_UDP) {
		__be32 source_ip =
			(reverse->route_value.flags & MUP_FLAG_RETURN_POOL) ?
			pool_addr :
			(reverse->route_value.flags & MUP_FLAG_RETURN_IP) ?
			reverse->route_value.return_ip :
			reverse->route_value.server_local_ip;
		if (partial)
			result = mup_rewrite_udp_partial(
				packet, source_ip,
				reverse->route_key.client.advertised_ip,
				source_port, listen_port,
				reverse->route_key.peer_token);
		else
			result = mup_rewrite_udp(
				packet, source_ip,
				reverse->route_key.client.advertised_ip,
				source_port, listen_port);
		if (result)
			return count_and_drop(skb, MUP_DROP_CHECKSUM);
	} else if (reverse->route_value.transport == MUP_TRANSPORT_ICMP) {
		__be32 source_ip;
		__be32 destination_ip;
		__u8 type;

		if (reverse->route_value.flags &
		    (MUP_FLAG_RETURN_IP | MUP_FLAG_RETURN_POOL)) {
			source_ip = reverse->route_key.client.advertised_ip;
			destination_ip =
				(reverse->route_value.flags & MUP_FLAG_RETURN_POOL) ?
				pool_addr : reverse->route_value.return_ip;
			type = MUP_ICMP_ECHO_REQUEST;
		} else {
			source_ip = reverse->route_value.server_local_ip;
			destination_ip = reverse->route_key.client.advertised_ip;
			type = MUP_ICMP_ECHO_REPLY;
		}
		if (partial)
			result = rewrite_icmp_partial(
				skb, packet, source_ip, destination_ip, type,
				reverse->route_value.server_port,
				reverse->route_key.peer_token);
		else
			result = mup_rewrite_icmp(
				packet, source_ip, destination_ip, type,
				source_port,
				mup_src_has(reverse->route_value.src_first,
					    reverse->route_value.src_last) ?
				MUP_ICMP_SEQUENCE(
					(reverse->route_value.path_id & 7) + 1,
					reverse->route_key.peer_token) :
				(__u16)reverse->route_key.peer_token);
		if (result)
			return count_and_drop(skb, MUP_DROP_CHECKSUM);
	} else {
		return count_and_drop(skb, MUP_DROP_TRANSPORT);
	}
	if (at_egress && reverse->route_value.ifindex == skb->ifindex &&
	    prepare_clone_l2(skb, packet, skb->ifindex) == MUP_DROP_NONE)
		return TC_ACT_OK;
	return redirect_packet(reverse->route_value.ifindex);
}

SEC("tc")
int mup_server_ingress(struct __sk_buff *skb)
{
	struct mup_packet packet = {};
	struct server_config_v1 *configuration;
	struct server_ports_v1 *ports;
	struct registered_path_key_v1 path_key = {};
	struct registered_path_value_v1 *path;
	struct registration_value_v1 *registration;
	struct server_reverse_value_v1 *reverse;
	struct server_route_key_v1 route_key = {};
	struct server_route_value_v1 observed = {};
	struct target_ingress_v1 *inject;
	__u32 configuration_key = 0;
	__u32 peer_token = 0;
	__u16 target_port = 0;
	__u16 reserved_port = 0;
	__u32 in_ports;
	__u32 tag;
	__u64 now;
	int result;

	result = parse_ipv4_l4(skb, &packet);
	if (result != MUP_DROP_NONE)
		return MUP_TCX_NEXT;
	configuration = bpf_map_lookup_elem(&server_config, &configuration_key);
	if (!configuration)
		return MUP_TCX_NEXT;

	inject = bpf_map_lookup_elem(&target_ingress, &configuration_key);
	if (inject && !inject->ifindex)
		inject = 0;
	/*
	 * With ingress delivery, the replies of the target leave through the
	 * egress hook, where mup_server_egress catches them.
	 */
	if (!inject && packet.transport == MUP_TRANSPORT_UDP &&
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
		/*
		 * A target on this host answers from a local socket, so its
		 * packets have CHECKSUM_PARTIAL, and the device completes the
		 * checksum. The partial rewrites leave the checksum to it.
		 */
		return server_target_reply(
			skb, &packet, reverse,
			configuration->target_ip == configuration->source_ip, 0);
	}

	ports = bpf_map_lookup_elem(&server_ports, &configuration_key);
	if (ports && ports->last >= ports->first)
		in_ports = packet.server_port >= ports->first &&
			   packet.server_port <= ports->last;
	else
		in_ports = packet.server_port == configuration->server_port;
	/*
	 * An Echo packet of a path with a source range has a path tag, and its
	 * identifier is a random value of the range, which need not lie in the
	 * server ports. Only an untagged packet needs a server port here.
	 */
	tag = mup_icmp_tag(&packet);
	if (!in_ports && !tag)
		return MUP_TCX_NEXT;
	if (is_mup_control(&packet))
		return MUP_TCX_NEXT;
	if (packet.transport == MUP_TRANSPORT_ICMP) {
		struct mup_icmphdr *icmp = packet.l4;
		if ((icmp->type != MUP_ICMP_ECHO_REQUEST &&
		     icmp->type != MUP_ICMP_ECHO_REPLY) || icmp->code != 0)
			return MUP_TCX_NEXT;
	}
	path_key.source_ip = packet.ipv4->source;
	path_key.local_ip = packet.ipv4->destination;
	path_key.transport = packet.transport;
	path = 0;
	/*
	 * A tagged packet looks up the tagged key of its path, and it is data
	 * of that path only when the range of the path holds its identifier.
	 * Otherwise, and for an untagged packet, the exact key of a packet on a
	 * server port decides, as for a path without a range.
	 */
	if (tag) {
		path_key.tag = tag;
		path = bpf_map_lookup_elem(&registered_paths, &path_key);
		if (path && !mup_src_contains(path->src_first, path->src_last,
					      packet.server_port))
			path = 0;
		/*
		 * The identifier of a tagged packet is random, so the route
		 * keeps the server port of the path. Each packet would move
		 * the route otherwise.
		 */
		if (path)
			observed.server_port = path->server_port;
	}
	if (!path && in_ports) {
		path_key.server_port = packet.server_port;
		path_key.tag = 0;
		observed.server_port = packet.server_port;
		path = bpf_map_lookup_elem(&registered_paths, &path_key);
	}
	/*
	 * A UDP server port is only a port number, so other traffic of the host
	 * can use it too. For example, a NAT that masquerades a flow to a pod
	 * can pick a port of the server range, and the replies of the pod then
	 * come here before conntrack restores their address. A UDP packet
	 * without a registered path thus goes on unchanged.
	 */
	if (!path && packet.transport == MUP_TRANSPORT_UDP)
		return MUP_TCX_NEXT;
	result = validate_wg(&packet, 1, &peer_token);
	if (result != MUP_DROP_NONE) {
		if (packet.transport == MUP_TRANSPORT_ICMP)
			return MUP_TCX_NEXT;
		return count_and_drop(skb, result);
	}
	/*
	 * An Echo Request with a WireGuard message is not a normal ping. Without
	 * a registered path, for example before the ACK of a new client, the
	 * kernel would echo the message back, and the client would take the
	 * reply as a downstream packet. This holds for a tagged packet outside
	 * the server ports too.
	 */
	if (!path)
		return count_and_drop(skb, MUP_DROP_NOT_REGISTERED);
	/*
	 * A reflected upstream arrives as an Echo Reply from the via host, and
	 * its registered path has MUP_FLAG_UP_REFLECT. Another Echo Reply with a
	 * WireGuard payload is not a reflected upstream, so it goes on to the
	 * kernel.
	 */
	if (packet.transport == MUP_TRANSPORT_ICMP) {
		struct mup_icmphdr *icmp = packet.l4;
		if (icmp->type == MUP_ICMP_ECHO_REPLY &&
		    !(path->flags & MUP_FLAG_UP_REFLECT))
			return MUP_TCX_NEXT;
	}
	/*
	 * The packet is data of the registered path, so it counts on that path
	 * before any later drop. A tagged key and each member of an ingress
	 * reflect pool have their own entry, with the path ID of the path, so
	 * they all count on the one path. The path ID is a plain number, like
	 * the listen port.
	 */
	mup_count_server_path(path->client.advertised_ip,
			      path->client.instance_nonce, path->path_id,
			      MUP_PATH_COUNTER_INGRESS, mup_packet_length(&packet));

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
	observed.transport = packet.transport;
	observed.flags = path->flags;
	observed.path_id = path->path_id;
	observed.client_source_ip = packet.ipv4->source;
	observed.server_local_ip = packet.ipv4->destination;
	observed.return_ip = path->return_ip;
	observed.ifindex = skb->ifindex;
	observed.listen_port = path->listen_port;
	observed.src_first = path->src_first;
	observed.src_last = path->src_last;
	if (configuration->target_ip == configuration->source_ip)
		reserved_port = configuration->target_port;
	result = get_or_create_server_route(&route_key, &observed, reserved_port,
					    &target_port);
	if (result != MUP_DROP_NONE)
		return count_and_drop(skb, result);
	/*
	 * With ingress delivery, the packet comes from the advertised IP of the
	 * client, so the target answers it there, and the answer leaves through
	 * the egress hook of the target interface.
	 */
	if (complete_udp_checksum(skb, &packet) ||
	    mup_clear_peer_token(&packet) ||
	    mup_rewrite_udp(&packet,
			    inject ? route_key.client.advertised_ip :
				     configuration->source_ip,
			    configuration->target_ip, target_port,
			    configuration->target_port))
		return count_and_drop(skb, MUP_DROP_CHECKSUM);
	if (inject) {
#pragma clang loop unroll(full)
		for (int index = 0; index < 6; index++)
			packet.ethernet->destination[index] = inject->mac[index];
		return bpf_redirect(inject->ifindex, BPF_F_INGRESS);
	}

	return redirect_packet(configuration->ifindex);
}

/*
 * mup_server_egress catches the replies of a target with ingress delivery.
 * The target answers the advertised IP of the client at the target port of the
 * route. An earlier egress program can rewrite the reply source to the target
 * address, as a WireGuard router does, so this program must run after it. Every
 * packet of the interface passes here, so a cheap header check comes first,
 * and every other packet goes on unchanged.
 */
SEC("tc")
int mup_server_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *ethernet = data;
	struct mup_iphdr *ipv4 = (void *)(ethernet + 1);
	struct mup_udphdr *udp = (void *)(ipv4 + 1);
	struct mup_packet packet = {};
	struct server_config_v1 *configuration;
	struct target_ingress_v1 *inject;
	struct server_reverse_value_v1 *reverse;
	__u32 configuration_key = 0;

	if ((void *)(udp + 1) > data_end)
		return MUP_TCX_NEXT;
	if (mup_read_be16((const __u8 *)&ethernet->protocol) != MUP_ETH_P_IPV4 ||
	    ipv4->version_ihl != 0x45 || ipv4->protocol != MUP_IPPROTO_UDP)
		return MUP_TCX_NEXT;
	configuration = bpf_map_lookup_elem(&server_config, &configuration_key);
	if (!configuration || ipv4->source != configuration->target_ip ||
	    mup_read_be16((const __u8 *)&udp->source) !=
		    configuration->target_port)
		return MUP_TCX_NEXT;
	inject = bpf_map_lookup_elem(&target_ingress, &configuration_key);
	if (!inject || !inject->ifindex || inject->ifindex != skb->ifindex)
		return MUP_TCX_NEXT;
	if (parse_ipv4_l4(skb, &packet) != MUP_DROP_NONE ||
	    packet.transport != MUP_TRANSPORT_UDP)
		return MUP_TCX_NEXT;
	reverse = bpf_map_lookup_elem(&server_route_by_port,
				      &packet.destination_port);
	if (!reverse ||
	    packet.ipv4->destination != reverse->route_key.client.advertised_ip)
		return MUP_TCX_NEXT;
	return server_target_reply(skb, &packet, reverse,
				   mup_udp_is_partial(&packet), 1);
}

static __always_inline void bridge_count(__u32 key, __u32 bytes)
{
	__u64 *counter;

	counter = bpf_map_lookup_elem(&bridge_counters, &key);
	if (counter)
		*counter += 1;
	key++;
	counter = bpf_map_lookup_elem(&bridge_counters, &key);
	if (counter)
		*counter += bytes;
}

/*
 * bridge_is_mup reports a MUP packet: a control frame, or a WireGuard message
 * with a peer token, in UDP or in an ICMP Echo.
 */
static __always_inline int bridge_is_mup(const struct mup_packet *packet)
{
	__u32 peer_token = 0;

	if (packet->transport == MUP_TRANSPORT_ICMP) {
		struct mup_icmphdr *icmp = packet->l4;

		if ((icmp->type != MUP_ICMP_ECHO_REQUEST &&
		     icmp->type != MUP_ICMP_ECHO_REPLY) ||
		    icmp->code != 0)
			return 0;
	}
	return is_mup_control(packet) ||
	       validate_wg(packet, 1, &peer_token) == MUP_DROP_NONE;
}

/*
 * bridge_is_wrapped reports a bridge wrapper: a UDP payload, or the payload of
 * an ICMP Echo Reply, that starts with the bridge magic. A reflector answers
 * the Echo Request of an ICMP bridge via path with that Echo Reply. An Echo
 * Request with the magic is not a wrapper.
 */
static __always_inline int bridge_is_wrapped(const struct mup_packet *packet)
{
	if (packet->transport == MUP_TRANSPORT_ICMP) {
		const struct mup_icmphdr *icmp = packet->l4;

		if (icmp->type != MUP_ICMP_ECHO_REPLY || icmp->code != 0)
			return 0;
	} else if (packet->transport != MUP_TRANSPORT_UDP) {
		return 0;
	}
	return mup_payload_fits(packet, MUP_BRIDGE_HEADER_LEN + 8) &&
	       packet->payload[0] == MUP_BRIDGE_MAGIC_0 &&
	       packet->payload[1] == MUP_BRIDGE_MAGIC_1;
}

/*
 * bridge_send redirects a packet to the interface of the route to its
 * destination. The lookup is the lookup of a forwarded packet, so the bridge
 * host needs IPv4 forwarding.
 */
static __always_inline int bridge_send(struct __sk_buff *skb,
				       const struct mup_packet *packet)
{
	struct bpf_fib_lookup fib = {};
	long result;

	fib.family = AF_INET;
	fib.l4_protocol = packet->ipv4->protocol;
	fib.tot_len = mup_read_be16((const __u8 *)&packet->ipv4->total_length);
	fib.ifindex = skb->ifindex;
	fib.tos = packet->ipv4->tos;
	fib.ipv4_src = packet->ipv4->source;
	fib.ipv4_dst = packet->ipv4->destination;
	result = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
	if (result != BPF_FIB_LKUP_RET_SUCCESS &&
	    result != BPF_FIB_LKUP_RET_NO_NEIGH)
		return count_and_drop(skb, MUP_DROP_FIB);
	return redirect_packet(fib.ifindex);
}

/*
 * mup_bridge_ingress runs on a MUP bridge. A MUP packet from a client to a
 * port of the bridge goes on to the server of the bridge, from the same
 * source. A wrapped reply from the server or an allowed sender loses its
 * wrapper and goes on to its inner destination, with its inner source. The
 * wrapper is UDP, or an ICMP Echo Reply that a reflector sends. For ICMP the
 * identifier is the port that picks the entry. Every
 * other packet goes on to the kernel, so a normal ping still gets its reply.
 * The bridge has up to MUP_MAX_BRIDGES entries, and the port of a packet
 * picks the entry with its server and its allowed senders.
 */
SEC("tc")
int mup_bridge_ingress(struct __sk_buff *skb)
{
	struct mup_packet packet = {};
	struct bridge_config_v1 *configuration;
	struct bridge_allow_key_v1 sender = {};
	__u32 bridge = 0;
	__be32 server_ip = 0;
	__u8 inner_protocol;
	int result;

	result = parse_ipv4_l4(skb, &packet);
	if (result != MUP_DROP_NONE)
		return MUP_TCX_NEXT;
	/*
	 * The address check comes before the entry search. A packet to another
	 * host then leaves after one lookup, and only a packet to the bridge
	 * host pays for the search of the entries.
	 */
	if (!bpf_map_lookup_elem(&bridge_addresses, &packet.ipv4->destination))
		return MUP_TCX_NEXT;
	/*
	 * The first used entry whose port range holds the port of the packet
	 * takes the packet. Go keeps the port ranges of the entries apart, so
	 * at most one entry matches. The loop copies the server of the entry,
	 * because a map value pointer must not be used after a helper changes
	 * the packet.
	 */
#pragma clang loop unroll(full)
	for (int index = 0; index < MUP_MAX_BRIDGES; index++) {
		__u32 configuration_key = index;

		configuration = bpf_map_lookup_elem(&bridge_config,
						    &configuration_key);
		if (!configuration || !configuration->server_ip ||
		    packet.server_port < configuration->port_first ||
		    packet.server_port > configuration->port_last)
			continue;
		bridge = index;
		server_ip = configuration->server_ip;
		break;
	}
	if (!server_ip)
		return MUP_TCX_NEXT;

	if (bridge_is_wrapped(&packet)) {
		sender.prefixlen = 64;
		sender.bridge = bridge;
		sender.address = packet.ipv4->source;
		if (!bpf_map_lookup_elem(&bridge_allow, &sender))
			return count_and_drop(skb, MUP_DROP_BRIDGE_SOURCE);
		inner_protocol = packet.payload[3];
		if (packet.payload[2] != MUP_BRIDGE_VERSION ||
		    (inner_protocol != MUP_IPPROTO_UDP &&
		     inner_protocol != MUP_IPPROTO_ICMP))
			return count_and_drop(skb, MUP_DROP_BRIDGE_PACKET);
		if (mup_bridge_unwrap(skb) != MUP_DROP_NONE)
			return count_and_drop(skb, MUP_DROP_BRIDGE_PACKET);
		packet = (struct mup_packet){};
		if (parse_ipv4_l4(skb, &packet) != MUP_DROP_NONE ||
		    !bridge_is_mup(&packet))
			return count_and_drop(skb, MUP_DROP_BRIDGE_PACKET);
		/*
		 * The sender leaves the UDP checksum of a packet from a local
		 * socket to its device. A device that finds the UDP header by
		 * the IPv4 header, for example vmxnet3, does not complete a
		 * checksum behind the wrapper, so the inner packet still holds
		 * the pseudo-header sum only, and its receiver would drop it.
		 * The bridge computes the checksum of such a packet.
		 */
		if (mup_udp_is_partial(&packet)) {
			__u8 *check = packet.l4;

			check[6] = 0;
			check[7] = 0;
			if (complete_udp_checksum(skb, &packet))
				return count_and_drop(skb, MUP_DROP_CHECKSUM);
		}
		bridge_count(MUP_BRIDGE_DOWN_PACKETS, skb->len);
		return bridge_send(skb, &packet);
	}

	if (packet.ipv4->source == server_ip || !bridge_is_mup(&packet))
		return MUP_TCX_NEXT;
	if (packet.transport == MUP_TRANSPORT_ICMP) {
		struct mup_icmphdr *icmp = packet.l4;

		if (icmp->type != MUP_ICMP_ECHO_REQUEST)
			return MUP_TCX_NEXT;
		result = mup_rewrite_icmp(&packet, packet.ipv4->source,
					  server_ip, MUP_ICMP_ECHO_REQUEST,
					  packet.server_port,
					  mup_read_be16((const __u8 *)&icmp->sequence));
	} else {
		if (complete_udp_checksum(skb, &packet))
			return count_and_drop(skb, MUP_DROP_CHECKSUM);
		result = mup_rewrite_udp(&packet, packet.ipv4->source, server_ip,
					 packet.source_port,
					 packet.destination_port);
	}
	if (result)
		return count_and_drop(skb, MUP_DROP_CHECKSUM);
	bridge_count(MUP_BRIDGE_UP_PACKETS, skb->len);
	return bridge_send(skb, &packet);
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
