#pragma once

#define MUP_ABI_VERSION 1
#define MUP_CONTROL_MAGIC 0x4d555043U
#define MUP_CONTROL_FRAME_LEN 48
#define MUP_MAX_PEER_TOKEN 4095U
#define MUP_MAX_ROUTES_PER_SOURCE 1024U
#define MUP_TCX_NEXT (-1)
#define MUP_FLAG_RETURN_IP (1U << 0)
/*
 * A route with MUP_FLAG_RETURN_POOL returns through a pool of addresses. The
 * return_ip field holds the pool base, and the prefix field holds the prefix
 * length. MUP_FLAG_BALANCE_PER_PACKET picks the per-packet balance mode, and a
 * route without it uses the per-peer mode.
 */
#define MUP_FLAG_RETURN_POOL (1U << 1)
#define MUP_FLAG_BALANCE_PER_PACKET (1U << 2)
/*
 * A server down path with MUP_FLAG_BRIDGE goes through a MUP bridge. The
 * server_ip field holds the bridge address, and the server wraps each reply
 * in a UDP packet from local_ip to the bridge.
 */
#define MUP_FLAG_BRIDGE (1U << 4)
/*
 * A client up path with MUP_FLAG_UP_REFLECT reflects the upstream through its
 * return_ip, or through one member of its pool. On an ICMP path the client
 * sends an Echo Request to the member with the server as the source. On a UDP
 * path it sends to the server with the member as the source. A registered path
 * with the flag on the server accepts the reflected upstream from that source,
 * including an ICMP Echo Reply.
 */
#define MUP_FLAG_UP_REFLECT (1U << 5)
/*
 * A server down path with MUP_FLAG_BRIDGE and MUP_FLAG_BRIDGE_VIA applies its
 * return IP or pool to the leg to the bridge. The server wraps the direct
 * reply from the bridge address in a UDP packet from the member to the
 * bridge. It must match protocol.ControlFlagBridgeVia.
 */
#define MUP_FLAG_BRIDGE_VIA (1U << 6)
#define MUP_MAX_POOL 16
/*
 * MUP_MAX_BRIDGES is the number of entries of a bridge. It must match
 * dataplane.MaxBridges.
 */
#define MUP_MAX_BRIDGES 8
/*
 * The bridge wrapper is a UDP header and a 12-byte bridge header between the
 * IPv4 header and the transport header of a packet. The bridge header holds
 * the magic "MB", the version, the inner protocol, and the inner source and
 * destination addresses.
 */
#define MUP_BRIDGE_MAGIC_0 0x4d
#define MUP_BRIDGE_MAGIC_1 0x42
#define MUP_BRIDGE_VERSION 1
#define MUP_BRIDGE_HEADER_LEN 12
#define MUP_BRIDGE_OVERHEAD 20
/*
 * A group with MUP_GROUP_FLAG_DEDUP gets copies of each downstream packet on
 * several down paths, so the client drops the later copies.
 */
#define MUP_GROUP_FLAG_DEDUP (1U << 0)

enum mup_mode {
	MUP_MODE_FALLBACK = 0,
	MUP_MODE_BALANCER = 1,
	MUP_MODE_BURST = 2,
};

enum mup_transport_id {
	MUP_TRANSPORT_UDP = 0,
	MUP_TRANSPORT_ICMP = 1,
};

enum mup_control_type {
	MUP_CONTROL_REGISTER = 1,
	MUP_CONTROL_REGISTER_ACK = 2,
	MUP_CONTROL_PROBE = 3,
	MUP_CONTROL_PROBE_REPLY = 4,
	MUP_CONTROL_DEREGISTER = 5,
	MUP_CONTROL_ERROR = 6,
	MUP_CONTROL_DOWN_REGISTER = 7,
};

enum mup_drop_reason {
	MUP_DROP_NONE = 0,
	MUP_DROP_MALFORMED_IPV4 = 1,
	MUP_DROP_IPV4_OPTIONS = 2,
	MUP_DROP_IPV4_FRAGMENT = 3,
	MUP_DROP_MALFORMED_L4 = 4,
	MUP_DROP_WG_TYPE = 5,
	MUP_DROP_WG_LENGTH = 6,
	MUP_DROP_WG_RESERVED = 7,
	MUP_DROP_NOT_REGISTERED = 8,
	MUP_DROP_PATH_MISMATCH = 9,
	MUP_DROP_TRANSPORT = 10,
	MUP_DROP_PEER_TOKEN_POOL = 11,
	MUP_DROP_TARGET_PORT_POOL = 12,
	MUP_DROP_MAP_INVARIANT = 13,
	MUP_DROP_ROUTE_MISS = 14,
	MUP_DROP_NO_PATH = 15,
	MUP_DROP_DUPLICATE = 16,
	MUP_DROP_FIB = 17,
	MUP_DROP_NEIGHBOR = 18,
	MUP_DROP_TAIL_CALL = 19,
	MUP_DROP_CHECKSUM = 20,
	MUP_DROP_SOURCE_LIMIT = 21,
	MUP_DROP_DOWNSTREAM_SOURCE = 22,
	MUP_DROP_BRIDGE_SOURCE = 23,
	MUP_DROP_BRIDGE_PACKET = 24,
	MUP_DROP_BRIDGE_SIZE = 25,
	MUP_DROP_REASON_COUNT = 26,
};

struct control_v1 {
	__be32 magic;
	__u8 version;
	__u8 type;
	__u8 transport;
	__u8 flags;
	__be16 length;
	__be16 status;
	__be16 path_id;
	__be16 listen_port;
	__be16 server_port;
	__be16 reserved;
	__be32 advertised_ip;
	__be32 return_ip;
	__be64 instance_nonce;
	__be32 sequence;
	__be32 lease_seconds;
	__be32 reserved_tail;
} __attribute__((packed));

struct client_key_v1 {
	__be32 advertised_ip;
	__u32 padding;
	__be64 instance_nonce;
};

struct server_route_key_v1 {
	struct client_key_v1 client;
	__be32 peer_token;
	__u32 padding;
};

struct registered_path_key_v1 {
	__be32 source_ip;
	__be32 local_ip;
	__be16 server_port;
	__u8 transport;
	__u8 padding;
};

struct client_config_v1 {
	__be64 instance_nonce;
	__be32 advertised_ip;
	__u32 generation;
};

/*
 * The peers of one listen port use only the paths in path_mask. A group with
 * separate down paths also accepts replies from the down paths in down_mask.
 * The return_ip field is not used.
 */
struct path_group_v1 {
	__be32 return_ip;
	__u8 mode;
	__u8 flags;
	__u8 path_mask;
	__u8 down_mask;
};

/*
 * client_down_path_v1 is one down path of a client, by down path ID. The
 * client accepts a reply from server_ip, from return_ip with
 * MUP_FLAG_RETURN_IP, or from the pool of return_ip and prefix with
 * MUP_FLAG_RETURN_POOL. The program writes last_seen_ns for each reply.
 */
struct client_down_path_v1 {
	__be32 server_ip;
	__be32 return_ip;
	__be16 server_port;
	__u8 transport;
	__u8 flags;
	__u8 prefix;
	__u8 padding[3];
	__u64 last_seen_ns;
};

/* The client drops a second copy of a downstream burst packet. */
struct client_duplicate_key_v1 {
	__be32 peer_token;
	__u8 identity[24];
};

/*
 * down_group_key_v1 names the down group of one listen port of a client. All
 * groups of a client share the client key, so the listen port tells them apart.
 */
struct down_group_key_v1 {
	struct client_key_v1 client;
	__be16 listen_port;
	__u8 padding[6];
};

/*
 * down_group_v1 holds the down paths of one group of a client on a server,
 * keyed by the client key and the listen port. The server program picks a
 * down path for each reply of the group with mode, among the paths in
 * path_mask & healthy_mask. The paths in icmp_mask use ICMP. Go writes it from
 * the DOWN_REGISTER frames and the probe replies.
 */
struct down_group_v1 {
	__u8 mode;
	__u8 path_mask;
	__u8 healthy_mask;
	__u8 icmp_mask;
};

struct down_path_key_v1 {
	struct client_key_v1 client;
	__u32 path_id;
	__u32 padding;
};

/*
 * down_path_v1 is one down path of a client on a server. A direct path sends
 * from server_ip. A path with MUP_FLAG_RETURN_IP returns through return_ip. A
 * path with MUP_FLAG_RETURN_POOL returns through the first count members,
 * which are the healthy members of the pool for this client. A path with
 * MUP_FLAG_BRIDGE wraps the reply from local_ip to the bridge at server_ip.
 * With MUP_FLAG_BRIDGE_VIA as well, the wrapper is from the member instead.
 */
struct down_path_v1 {
	__be32 server_ip;
	__be32 return_ip;
	__u32 ifindex;
	__be16 server_port;
	__u8 transport;
	__u8 flags;
	__u32 count;
	__be32 local_ip;
	__be32 members[MUP_MAX_POOL];
};

/*
 * bridge_config_v1 is one entry of a bridge: its server, and the ports and
 * ICMP identifiers that it takes. An entry with a zero server_ip is unused.
 */
struct bridge_config_v1 {
	__be32 server_ip;
	__u16 port_first;
	__u16 port_last;
};

/*
 * bridge_allow_key_v1 is the key of the LPM trie of the bridge senders. The
 * LPM data is the 4 bytes of bridge, the entry index, followed by the 4 bytes
 * of address. A sender prefix of N bits has a prefixlen of 32 + N, and the
 * program looks up a sender with a prefixlen of 64.
 */
struct bridge_allow_key_v1 {
	__u32 prefixlen;
	__u32 bridge;
	__be32 address;
};

enum mup_bridge_counter {
	MUP_BRIDGE_UP_PACKETS = 0,
	MUP_BRIDGE_UP_BYTES = 1,
	MUP_BRIDGE_DOWN_PACKETS = 2,
	MUP_BRIDGE_DOWN_BYTES = 3,
	MUP_BRIDGE_COUNTERS = 4,
};

struct server_config_v1 {
	__be32 target_ip;
	__be32 source_ip;
	__u32 ifindex;
	__be16 target_port;
	__be16 server_port;
};

/*
 * target_ingress_v1 turns on the ingress delivery of a target on the server
 * host, for example a WireGuard router with a TC fast path on that interface.
 * The server injects each upstream packet into the ingress hook of ifindex,
 * from the advertised IP of the client and the target port of the route, with
 * mac as the Ethernet destination. It catches the replies of the target in
 * the egress hook of the same interface. An ifindex of zero turns it off.
 */
struct target_ingress_v1 {
	__u32 ifindex;
	__u8 mac[6];
	__u8 padding[2];
};

/*
 * The server accepts every port from first to last. server_config_v1 keeps
 * the first port, so a server without this entry accepts only that port.
 */
struct server_ports_v1 {
	__u16 first;
	__u16 last;
};

struct registration_value_v1 {
	__be32 return_ip;
	__be16 listen_port;
	__u8 flags;
	__u8 path_count;
	__u64 expires_at_ns;
};

struct registered_path_value_v1 {
	struct client_key_v1 client;
	__u64 expires_at_ns;
	__be16 path_id;
	__u8 flags;
	__u8 prefix;
	__be32 return_ip;
	/* The listen port of the group whose REGISTER frame made the path. */
	__be16 listen_port;
	__u8 padding[6];
};

struct peer_endpoint_key_v1 {
	__be32 source_ip;
	__be32 local_ip;
	__be16 source_port;
	__be16 listen_port;
};

struct peer_token_value_v1 {
	__be32 peer_token;
	__u32 padding;
	__u64 last_seen_ns;
};

struct peer_endpoint_value_v1 {
	struct peer_endpoint_key_v1 endpoint;
	__u32 ifindex;
	__u64 last_seen_ns;
};

struct server_route_value_v1 {
	__be16 target_port;
	__be16 server_port;
	__u8 transport;
	__u8 flags;
	__be16 path_id;
	__be32 client_source_ip;
	__be32 server_local_ip;
	__be32 return_ip;
	__u32 ifindex;
	__u64 last_seen_ns;
	/* The listen port of the group of the path that the route follows. */
	__be16 listen_port;
	__u8 padding[6];
};

struct server_reverse_value_v1 {
	struct server_route_key_v1 route_key;
	struct server_route_value_v1 route_value;
};

struct path_config_v1 {
	__be32 destination_ip;
	__be32 source_ip;
	__u32 ifindex;
	__be16 server_port;
	__u8 transport;
	__u8 priority;
	/*
	 * bridge is the address of a bridge that emits the reflected upstream of
	 * an up reflect route. The client egress wraps the reflected packet for
	 * the bridge, because the client cannot send the spoofed packet itself.
	 * It is zero on a route that the client sends itself.
	 */
	__be32 bridge;
};

/*
 * The return IP of a client path slot, set when flags has MUP_FLAG_RETURN_IP.
 * With MUP_FLAG_RETURN_POOL the return_ip is a pool base and prefix is its
 * prefix length, so the client accepts any downstream source in the range.
 */
struct path_return_v1 {
	__be32 return_ip;
	__u8 flags;
	__u8 prefix;
	__u8 padding[2];
};

/*
 * up_reflect_v1 holds the reflect members of one client up path, by path slot.
 * The client reflects the upstream of the slot through the first count members,
 * which are the healthy members for the path. A single return IP is a pool of
 * one member. With MUP_FLAG_BALANCE_PER_PACKET the client steps a cursor for
 * each packet, and without it the client hashes the peer token to a member. The
 * client egress reads it when the slot has MUP_FLAG_UP_REFLECT.
 */
struct up_reflect_v1 {
	__u32 count;
	__u8 flags;
	__u8 padding[3];
	__be32 members[MUP_MAX_POOL];
};

/*
 * reflector_key_v1 names a return pool by its base and transport. A UDP route
 * and an ICMP route can share a range, and each keeps its own health.
 */
struct reflector_key_v1 {
	__be32 base;
	__u8 transport;
	__u8 padding[3];
};

/*
 * reflector_pool_v1 holds the reflectors of one pool, keyed by reflector_key_v1.
 * The Go prober writes it. count is the number of addresses, healthy_mask has
 * one bit for each healthy address, and addresses holds the pool members. The
 * server program reads it when it reflects a downstream reply.
 */
struct reflector_pool_v1 {
	__u32 count;
	__u64 healthy_mask;
	__be32 addresses[MUP_MAX_POOL];
};

struct path_state_v1 {
	__u32 generation;
	__u32 healthy_mask;
};

struct duplicate_key_v1 {
	struct server_route_key_v1 route;
	__u8 identity[24];
};

struct event_v1 {
	__u64 timestamp_ns;
	__u32 reason;
	__u32 ifindex;
	struct client_key_v1 client;
};

struct event_limit_v1 {
	struct bpf_spin_lock lock;
	__u32 emitted;
	__u64 window_started_ns;
};

_Static_assert(sizeof(struct control_v1) == 48, "control_v1 ABI");
_Static_assert(sizeof(struct client_key_v1) == 16, "client_key_v1 ABI");
_Static_assert(sizeof(struct server_route_key_v1) == 24, "server_route_key_v1 ABI");
_Static_assert(sizeof(struct registered_path_key_v1) == 12, "registered_path_key_v1 ABI");
_Static_assert(sizeof(struct client_config_v1) == 16, "client_config_v1 ABI");
_Static_assert(sizeof(struct path_group_v1) == 8, "path_group_v1 ABI");
_Static_assert(sizeof(struct server_config_v1) == 16, "server_config_v1 ABI");
_Static_assert(sizeof(struct server_ports_v1) == 4, "server_ports_v1 ABI");
_Static_assert(sizeof(struct target_ingress_v1) == 12, "target_ingress_v1 ABI");
_Static_assert(sizeof(struct registration_value_v1) == 16, "registration_value_v1 ABI");
_Static_assert(sizeof(struct registered_path_value_v1) == 40, "registered_path_value_v1 ABI");
_Static_assert(sizeof(struct peer_endpoint_key_v1) == 12, "peer_endpoint_key_v1 ABI");
_Static_assert(sizeof(struct peer_token_value_v1) == 16, "peer_token_value_v1 ABI");
_Static_assert(sizeof(struct peer_endpoint_value_v1) == 24, "peer_endpoint_value_v1 ABI");
_Static_assert(sizeof(struct server_route_value_v1) == 40, "server_route_value_v1 ABI");
_Static_assert(sizeof(struct server_reverse_value_v1) == 64, "server_reverse_value_v1 ABI");
_Static_assert(sizeof(struct path_config_v1) == 20, "path_config_v1 ABI");
_Static_assert(sizeof(struct path_return_v1) == 8, "path_return_v1 ABI");
_Static_assert(sizeof(struct up_reflect_v1) == 72, "up_reflect_v1 ABI");
_Static_assert(sizeof(struct reflector_key_v1) == 8, "reflector_key_v1 ABI");
_Static_assert(sizeof(struct reflector_pool_v1) == 80, "reflector_pool_v1 ABI");
_Static_assert(sizeof(struct path_state_v1) == 8, "path_state_v1 ABI");
_Static_assert(sizeof(struct duplicate_key_v1) == 48, "duplicate_key_v1 ABI");
_Static_assert(sizeof(struct event_v1) == 32, "event_v1 ABI");
_Static_assert(sizeof(struct client_down_path_v1) == 24, "client_down_path_v1 ABI");
_Static_assert(sizeof(struct client_duplicate_key_v1) == 28, "client_duplicate_key_v1 ABI");
_Static_assert(sizeof(struct down_group_key_v1) == 24, "down_group_key_v1 ABI");
_Static_assert(sizeof(struct down_group_v1) == 4, "down_group_v1 ABI");
_Static_assert(sizeof(struct down_path_key_v1) == 24, "down_path_key_v1 ABI");
_Static_assert(sizeof(struct down_path_v1) == 88, "down_path_v1 ABI");
_Static_assert(sizeof(struct bridge_config_v1) == 8, "bridge_config_v1 ABI");
_Static_assert(sizeof(struct bridge_allow_key_v1) == 12, "bridge_allow_key_v1 ABI");
_Static_assert(sizeof(struct event_limit_v1) == 16, "event_limit_v1 ABI");
