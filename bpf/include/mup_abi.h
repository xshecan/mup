#pragma once

#define MUP_ABI_VERSION 1
#define MUP_CONTROL_MAGIC 0x4d555043U
#define MUP_CONTROL_FRAME_LEN 48
#define MUP_MAX_PEER_TOKEN 4095U
#define MUP_TCX_NEXT (-1)
#define MUP_FLAG_RETURN_IP (1U << 0)

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
	MUP_DROP_RETURN_POLICY = 21,
	MUP_DROP_DOWNSTREAM_SOURCE = 22,
	MUP_DROP_REASON_COUNT = 23,
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

/* The peers of one listen port use only the paths in path_mask. */
struct path_group_v1 {
	__be32 return_ip;
	__u8 mode;
	__u8 flags;
	__u8 path_mask;
	__u8 padding;
};

struct server_config_v1 {
	__be32 target_ip;
	__be32 source_ip;
	__u32 ifindex;
	__be16 target_port;
	__be16 server_port;
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
_Static_assert(sizeof(struct registration_value_v1) == 16, "registration_value_v1 ABI");
_Static_assert(sizeof(struct registered_path_value_v1) == 32, "registered_path_value_v1 ABI");
_Static_assert(sizeof(struct peer_endpoint_key_v1) == 12, "peer_endpoint_key_v1 ABI");
_Static_assert(sizeof(struct peer_token_value_v1) == 16, "peer_token_value_v1 ABI");
_Static_assert(sizeof(struct peer_endpoint_value_v1) == 24, "peer_endpoint_value_v1 ABI");
_Static_assert(sizeof(struct server_route_value_v1) == 32, "server_route_value_v1 ABI");
_Static_assert(sizeof(struct server_reverse_value_v1) == 56, "server_reverse_value_v1 ABI");
_Static_assert(sizeof(struct path_config_v1) == 16, "path_config_v1 ABI");
_Static_assert(sizeof(struct path_state_v1) == 8, "path_state_v1 ABI");
_Static_assert(sizeof(struct duplicate_key_v1) == 48, "duplicate_key_v1 ABI");
_Static_assert(sizeof(struct event_v1) == 32, "event_v1 ABI");
_Static_assert(sizeof(struct event_limit_v1) == 16, "event_limit_v1 ABI");
