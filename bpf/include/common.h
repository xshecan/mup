#pragma once

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) typeof(value) *name
#define __always_inline inline __attribute__((always_inline))
#define LIBBPF_PIN_BY_NAME 1
#define MUP_PINNED __uint(pinning, LIBBPF_PIN_BY_NAME)

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

#define AF_INET 2
#define BPF_FIB_LOOKUP_OUTPUT (1U << 1)
#define BPF_FIB_LKUP_RET_SUCCESS 0

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_REDIRECT 7

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_RINGBUF = 27,
};

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
};

struct ethhdr {
	__u8 destination[6];
	__u8 source[6];
	__be16 protocol;
};

struct mup_iphdr {
	__u8 version_ihl;
	__u8 tos;
	__be16 total_length;
	__be16 id;
	__be16 fragment_offset;
	__u8 ttl;
	__u8 protocol;
	__be16 checksum;
	__be32 source;
	__be32 destination;
};

struct mup_udphdr {
	__be16 source;
	__be16 destination;
	__be16 length;
	__be16 checksum;
};

struct mup_icmphdr {
	__u8 type;
	__u8 code;
	__be16 checksum;
	__be16 identifier;
	__be16 sequence;
};

struct bpf_spin_lock {
	__u32 val;
};

/*
 * Kept byte-for-byte compatible with Linux UAPI struct bpf_fib_lookup.
 * MUP only fills the IPv4 fields, but the full unions preserve the helper ABI.
 */
struct bpf_fib_lookup {
	__u8 family;
	__u8 l4_protocol;
	__be16 sport;
	__be16 dport;
	union {
		__u16 tot_len;
		__u16 mtu_result;
	} __attribute__((packed, aligned(2)));
	__u32 ifindex;
	union {
		__u8 tos;
		__be32 flowinfo;
		__u32 rt_metric;
	};
	union {
		__be32 ipv4_src;
		__u32 ipv6_src[4];
	};
	union {
		__be32 ipv4_dst;
		__u32 ipv6_dst[4];
	};
	union {
		struct {
			__be16 h_vlan_proto;
			__be16 h_vlan_TCI;
		};
		__u32 tbid;
	};
	union {
		struct {
			__u32 mark;
			__u32 input_holes[2];
		};
		struct {
			__u8 smac[6];
			__u8 dmac[6];
		};
	};
};

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(const void *map, const void *key,
				   const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(const void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;
static long (*bpf_clone_redirect)(struct __sk_buff *skb, __u32 ifindex,
				  __u64 flags) = (void *)13;
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params,
			      int plen, __u32 flags) = (void *)69;
static long (*bpf_map_push_elem)(const void *map, const void *value,
				 __u64 flags) = (void *)87;
static long (*bpf_map_pop_elem)(const void *map, void *value) = (void *)88;
static void (*bpf_spin_lock)(struct bpf_spin_lock *lock) = (void *)93;
static void (*bpf_spin_unlock)(struct bpf_spin_lock *lock) = (void *)94;
static long (*bpf_redirect_neigh)(__u32 ifindex, const void *params,
				  int plen, __u64 flags) = (void *)152;
static void *(*bpf_ringbuf_reserve)(const void *ringbuf, __u64 size,
				    __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
