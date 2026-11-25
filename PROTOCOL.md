# MUP protocol

This document describes version 1 of the MUP protocol as the code implements it. It covers the packet formats, the control plane, the BPF maps, and the timers.

## Contents

1. [Terms](#terms)
2. [Topology](#topology)
3. [The peer token](#the-peer-token)
4. [Packet rewrites](#packet-rewrites)
5. [Transports and return modes](#transports-and-return-modes)
6. [Packet flow](#packet-flow)
7. [Path selection](#path-selection)
8. [Control plane](#control-plane)
9. [Path health](#path-health)
10. [Path measurement](#path-measurement)
11. [Loss tolerance and latency choice](#loss-tolerance-and-latency-choice)
12. [Bandwidth limit](#bandwidth-limit)
13. [Dataplane state](#dataplane-state)
14. [Lifetimes and cleanup](#lifetimes-and-cleanup)
15. [Input rules](#input-rules)
16. [Drop reasons](#drop-reasons)
17. [Attachment and restarts](#attachment-and-restarts)
18. [Observability](#observability)
19. [Control socket](#control-socket)
20. [Trust model](#trust-model)
21. [Limits](#limits)

## Terms

| Term | Meaning |
| --- | --- |
| WireGuard peer | A WireGuard endpoint that sends its packets to the MUP client. |
| WireGuard target | The one WireGuard endpoint behind the MUP server. The server `-r` flag sets it. |
| Path | One way from the client to a server. One client `-u` flag sets one path. |
| Ingress path | A path of a group with separate egress paths. It carries only the packets from the client to the server. |
| Egress path | A way that the server sends the replies of a group to the client. One `egress` route sets one egress path. |
| Bridge | A host that runs `mup bridge` between the clients and its servers. It has up to 8 entries, each with one server. One `bridges` entry sets one ingress path or egress path through it. An egress route with a `bridge` suffix also sets one egress path through it. |
| Bridge wrapper | The 20 bytes after the IPv4 header of a bridge reply: a UDP or ICMP Echo header, and the bridge header. |
| Group | One listen port with its mode and its paths. Each path has an optional return IP. |
| Port | The number in `-u SERVER:PORT` and in server `-p`. For UDP, it is the destination port. For ICMP, it is the Echo identifier. |
| Listen port | The client `-p` port of a group. The peers send to it, and egress packets arrive on it. |
| Advertised IP | The client address in client `-s`. The server sends all replies to it. |
| Source range | The values that the data packets of a path take as UDP source port or ICMP Echo identifier. `src FIRST-LAST` sets it. |
| Path tag | The 4 bits of the ICMP Echo sequence that name a path with a source range. |
| Return IP | The optional client `-r` address of a group. For UDP, it is the spoofed source of replies. For ICMP, it is the reflector. |
| Peer token | A client-local number from 1 to 4095 that names one WireGuard peer. |
| Instance nonce | A random nonzero 64-bit number that a client picks at each start. |
| Client key | The advertised IP and the instance nonce together. The server uses it to tell clients apart. |
| Route | The state that joins one peer to its token, or one token to its target port. |
| Target port | A UDP source port from 20000 to 60999 that the server gives to one route. |
| Lease | The time that a registration stays valid without a new REGISTER frame. |
| Quarantine | A wait time before a free token or port goes back into use. |
| Count code | A 32-bit packet count in a control frame. Zero means no count. |
| `TCX_NEXT` | The TCX verdict that passes a packet on to the kernel without a change. |

## Topology

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".docs/images/overview-dark.svg">
  <img alt="MUP topology from peers to the target" src=".docs/images/overview-light.svg">
</picture>

One MUP server serves many MUP clients. Each client serves many WireGuard peers and uses up to eight paths in all. Each server forwards all traffic to one WireGuard target. Each active client of a server must use an advertised IP that no other client of that server uses.

MUP has three ingress programs. `mup_client_ingress` runs on the client host, `mup_server_ingress` runs on the server host, and `mup_bridge_ingress` runs on a bridge host. Each program attaches to the TCX ingress hook of every Ethernet interface that is up at start. The loopback interface counts as an Ethernet interface. For a packet that MUP does not own, the program returns `TCX_NEXT`, and the kernel handles the packet as usual.

### Path groups

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".docs/images/groups-dark.svg">
  <img alt="Two path groups and their targets" src=".docs/images/groups-light.svg">
</picture>

A client can serve several WireGuard targets, with one group for each. A group joins one listen port to a mode and a set of paths, and each path has an optional return IP. The port that a peer sends to selects its group. All servers of a group must forward to the same target, because a WireGuard handshake fails against another identity.

The groups share the advertised IP, the instance nonce, the eight path slots, and the pool of tokens. A token is unique in the client, so an egress token gives the peer and its group. The client never moves a peer to another group.

The client configuration rejects one server address and port in two groups. The server keeps the listen port and the return IP of each registered path. It copies the listen port to each route that arrives on the path, and a reply goes to the listen port of its route. Two groups of one client key can thus use one server.

## The peer token

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".docs/images/packet-dark.svg">
  <img alt="One packet before and after a rewrite" src=".docs/images/packet-light.svg">
</picture>

A WireGuard message starts with a type byte and three reserved bytes. WireGuard sends the reserved bytes as zero. MUP uses them for the peer token while the packet travels between the MUP client and the MUP server. The token is a 24-bit big-endian number. Protocol v1 uses only the values 1 to 4095 and treats all other values as invalid.

The client keeps one token for each peer endpoint. A peer endpoint is the peer IP and port, the local IP, and the listen port. The server keys its routes by the client key and the token together, so two clients can use the same token. The token bytes are zero again before a WireGuard implementation reads the packet. WireGuard authentication and the handshake MACs thus stay valid.

## Packet rewrites

MUP rewrites every packet in place, as the hexdump in the previous section shows. A rewrite changes the IPv4 addresses, the IPv4 protocol field, all eight bytes of the UDP or ICMP header, and the peer token. UDP and ICMP headers are both eight bytes long. A packet can thus switch between UDP and ICMP without a change in length. The IPv4 total length, the TTL, the DF bit, and the WireGuard payload stay the same.

### Checksums

MUP computes the IPv4 header checksum again over the 20 header bytes. It updates the UDP or ICMP checksum incrementally, as RFC 1624 describes. The formula is `HC' = ~(~HC + ~m + m')`, where `m` holds the old words and `m'` holds the new words. First, it derives the sum of the payload from the old checksum and the old header words. Then it adds the new header words and writes the new checksum. The cost is the same for every packet size. MUP reads the payload bytes in only two cases, which the next paragraphs describe: a UDP checksum of zero and a partial checksum on an ICMP path.

A valid checksum stays valid after a rewrite, and a corrupt checksum stays corrupt. The receiver then drops the corrupt packet as usual. The UDP checksum covers the UDP pseudo-header, and the ICMP checksum does not. A computed UDP checksum of zero goes on the wire as 0xffff, as RFC 768 requires.

A UDP checksum field of zero gives no payload sum to update. IPv4 lets a sender that computes no checksum send zero. Some NAT devices also write zero for a computed checksum of zero, where RFC 768 requires 0xffff. About 1 packet in 65536 of their flows then arrives with zero, and plain WireGuard accepts it as a packet without a checksum. So MUP sums the payload of such a packet, up to 9216 bytes, writes its checksum, and then rewrites it as usual. If the payload is longer, MUP drops the packet and counts reason 20.

A target on the server host, for example `127.0.0.1`, answers from a local socket. Its replies have a partial checksum (`CHECKSUM_PARTIAL`): the UDP checksum field holds only the pseudo-header sum, and the network device adds the UDP header and the payload at send time. If the target IP equals the source IP of the target route, the server handles the target as local. The target can use any address of the server host, and the server reaches it through the loopback interface. On a UDP path, the server writes the new pseudo-header sum and leaves the rest to the device. On an ICMP path, the server computes the ICMP checksum from the payload and keeps the sequence at zero. It does not leave this checksum to the device, because some devices, for example vmxnet3, do not complete the partial checksum of an ICMP packet. A device that completes it writes a word at the UDP checksum offset, which is the Echo sequence field. If all words add up to 0xffff, a one's complement checksum is valid, so this word keeps the checksum valid. The client does not read the sequence, because the peer token is in the WireGuard bytes. The client does the same for a packet from WireGuard on the client host. That packet also comes through loopback with a partial checksum.

`protocol/rewrite.go` is a copy of the algorithm in `bpf/include/rewrite.h`. Its tests make sure that each incremental result matches a full checksum of the packet.

## Transports and return modes

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".docs/images/return-modes-dark.svg">
  <img alt="UDP and ICMP paths with direct or reflected replies" src=".docs/images/return-modes-light.svg">
</picture>

Each path uses UDP or ICMP. The return IP of a path sets the return mode of that path. The table shows the outer headers of each packet. In the table, "listen" is the listen port, "port" is the port of the path, and "token" is the peer token. The table shows a path without a source range. See [Source range](#source-range).

| Direction | Mode | Source | Destination | Transport header |
| --- | --- | --- | --- | --- |
| Ingress | UDP | `-s`:listen | server:port | UDP |
| Ingress | ICMP | `-s` | server | Echo Request, identifier = port, sequence = token |
| Egress | UDP direct | server:port | `-s`:listen | UDP |
| Egress | UDP reflected | return IP:port | `-s`:listen | UDP with a spoofed source |
| Egress | ICMP direct | server | `-s` | Echo Reply, identifier = port, sequence = token |
| Egress | ICMP reflected | `-s` | return IP | Echo Request, identifier = port, sequence = token |

In an egress packet, "server" is the server address that received the latest ingress packet of the route.

In the UDP reflected mode, the return IP host never receives the packet. The server only writes the return IP as the source. The networks between the server and the client must accept a spoofed source. A network that filters source addresses (BCP 38) drops these packets.

In the ICMP reflected mode, the server sends an Echo Request from `-s` to the reflector. The reflector answers with an Echo Reply to `-s`, which is the client. Any host that answers ping can be the reflector. The network between the server and the reflector must accept the spoofed source. The server sends the Echo Request out of the interface that received the traffic of the path. So the reflector must be reachable through that interface.

The client accepts an egress packet only from a source that a path of the group of the peer expects. The packet must also have the port and the transport of that path. If the path has a source range, the port of a UDP packet must be in the range. If the path has a return IP, the source must equal it. If the path has a return pool, the source must be in the pool range. If the path has neither, the source must be the server address of the path. The client drops any other egress packet and counts reason 22.

### Return pools

A return pool is a range of return IPs, for example `via 94.184.45.48/28`. The base must be the network address of the range.

The server picks one member of the pool for each egress packet. In the per-peer balance mode, all packets of one peer use one member. In the per-packet mode, each packet uses the next member. A pool has at most 16 members, and only a healthy member carries packets. If a pool has no healthy member, the server drops the packet and counts reason 15.

Every 2 seconds, the server sends one Echo Request to each host address of each pool range, up to 1024 addresses in each range. A /31 has two host addresses. In a larger range, the network address and the broadcast address are not host addresses. A host that replies within 1 second is live.

- An ICMP member must reply to ping, because it sends the Echo Reply to the client. The members are the live hosts. A member that misses 3 sweeps in a row is unhealthy, and a member that misses 15 sweeps leaves the pool.
- A UDP member is only a spoofed source, so it does not have to reply to ping. The members are the live hosts first, then the other hosts of the range in order. Every 2 seconds, the server sends a control probe to the client from each member as a spoofed source. The client sends a probe reply to the real server for each probe that arrives. A UDP member is healthy for 6 seconds after its latest probe reply.

If no member of a pool is healthy, the server answers each REGISTER of a path with that pool with the status NO_REFLECTOR. It still registers the path, so the path comes back once a reflector is healthy. A new pool is ready for 6 seconds after its first registration, before the first sweep and the first probe replies. The client counts a NO_REFLECTOR answer as a missed ACK, so the path becomes unhealthy after 3 of them. `mupctl paths` then shows the path as `unhealthy (no reflector)`. A client before this status cannot decode the answer, so it also counts it as missed.

If a probe reply names the client, the instance nonce, and the path of a live registration, the server accepts it. The member must also be in the pool of that path. When the number of live hosts of a pool changes, the server logs a line. `mupctl reflectors` shows each member and its health.

### Separate egress paths

A group can have separate egress paths. The `ingress` routes of the group are its ingress paths, and its `egress` routes are its egress paths. The client picks the ingress path of each ingress packet with the ingress mode. The server picks the egress path of each reply with the egress mode. So the two directions fail over on their own.

An egress path names the server address and port that send the replies, the transport, and an optional return IP or pool. Its return modes are the modes in the table, with these differences:

- A direct UDP egress path sends from its server address and port to `-s`:listen.
- A direct ICMP egress path sends an Echo Reply from its server address, with the port of the path as identifier.
- A reflected egress path uses its return IP, or a member of its pool, as the table shows.

The server address of an egress path must be an address of the server host. The server sends each reply out of the interface that holds that address. If the address is on a loopback interface, the server uses the route to the destination.

An ingress path has no return IP. The client also accepts a reply from the server of an ingress path, so an older server can still answer on the ingress paths.

### Source range

Every data packet of a path has a source value: the UDP source port, or the ICMP Echo identifier. Without a source range, this value is fixed. An ingress UDP packet leaves from the listen port of its group. An egress UDP packet leaves from the server port of the path. An ICMP packet of either direction has the server port of the path as its identifier.

A route with `src FIRST-LAST` has a source range. Each data packet of its path then takes a random value of the range. FIRST and LAST are from 1 to 65535. A network that limits one flow then sees many flows, and the packets can take different roads. The control frames keep the fixed port of the route.

The client keeps the range of each ingress path in `client_path_src`, and the range of each egress path in `client_down_src`. The server learns each range from flag bit 7 of the REGISTER frame or the EGRESS_REGISTER frame. These rules apply:

- UDP ingress: The server does not read the source port of an ingress packet. So a range on the client needs no change on the server.
- UDP egress: The client accepts a reply of the path when its source port is in the range. The configuration refuses two UDP egress routes of one client from one server address if their ranges overlap. It also refuses a range that holds the fixed port of another such route.
- ICMP: The peer token needs 12 of the 16 bits of the Echo sequence. Bits 12 to 15 carry the path tag. The tag is the path slot plus 1, from 1 to 8, on a packet of a path with a range. It is 0 on every other packet. Each side finds the path by the tag and makes sure that the identifier is in the range. So the identifier can vary.
- ICMP on the server: A tagged packet reaches its path also when its identifier is outside the server ports. The server looks up a key with the tag and no port. A tagged WireGuard message without a registered path counts reason 8, so the kernel does not echo it back.
- Partial checksum: A local socket whose device completes the checksum sends an ICMP packet with a partial checksum. This packet cannot carry the tag. It keeps the fixed identifier and no tag, and both sides accept this form on a path with a range. A device can write 0xffff into the sequence, so a tag above 8 counts as tag 0.
- Bridges: An ICMP ingress entry of a `bridges` list cannot have a range, because the bridge finds its entry by the identifier. On an egress path through a bridge, a UDP wrapper also takes a source port of the range. Its destination port stays the port of the entry. An Echo wrapper keeps the port of the entry as its identifier, and its sequence takes a value of the range.
- A client behind NAT cannot use a source range.
- A server before v0.5.1 refuses a frame with flag bit 7, so the path does not come up there. A UDP ingress range needs no server change.

### Bridges

A bridge has up to 8 entries, and each entry has one server. A bridge passes the ingress on to the server of the entry that holds the port of the packet. A path through a bridge names the bridge address in place of the server address. Only a group with separate egress paths has bridges.

An ingress bridge carries the ingress of a path. The client sends to the bridge in the same way as to a server. The bridge changes the destination to the server of the entry, and it keeps the source, the port, and the ICMP identifier. It updates the IPv4 checksum and the UDP checksum. So the server gets the same packet as from the client.

An egress bridge carries the replies of an egress path. The server rewrites each reply as for an egress route, with the bridge address as the server address of the path. A direct reply thus comes from the bridge address. Then the server puts the reply in the bridge wrapper. An egress bridge has three forms, and they differ in the return IP of the path and in the source of the wrapper. An egress route with a bridge suffix, `SERVER:PORT/t via X bridge B`, builds the reply as for an egress route with that via. The bridge then sends the reply with the source that the via needs. An egress bridge with a via, `B:PORT/t via X`, builds the direct reply from the bridge address. The server uses X, or a member of the pool, as the source of a UDP wrapper, or as the reflector of an Echo wrapper. An egress bridge without a via sends the wrapper from the server address, and the bridge sends the reply from its own address.

The server uses this UDP wrapper for each egress bridge, except for an ICMP entry with a via. That entry uses the Echo wrapper, which the next paragraphs describe.

| Part | Size | Content |
| --- | ---: | --- |
| IPv4 header | 20 | From the server to the bridge, with protocol UDP. The other fields do not change. |
| UDP header | 8 | The port of the egress path at both ends. The checksum is zero. |
| Bridge header | 12 | The magic 0x4d42 ("MB"), version 1, the inner protocol, the inner source address, and the inner destination address. |
| Inner header | 8 | The ICMP header of the reply, an Echo Reply from the bridge address, with no change. |
| Payload | n | The WireGuard message or the control frame, with no change. |

The transport header and the payload do not move. So the inner checksum stays valid, and a partial checksum stays partial. The server sends a UDP wrapper to the bridge through the interface of its route. The source of the UDP wrapper is the source address of the route. With a bridge via, it is the member. An Echo wrapper goes to X through the interface of its route, with the bridge address as its source. If the wrapped reply does not fit the MTU of that interface, the server drops it and counts reason 25. In the egress repeater mode, the server removes the wrapper again after the copy of an egress bridge. So the next egress path gets the reply as it was.

The Echo wrapper is the wrapper of an ICMP entry with a via. When the EGRESS_REGISTER has transport 1, flag bit 4, flag bit 6, and flag bit 0 or bit 1, the server uses it. The bridge must be v0.5.2 or later for this wrapper. The server sends the wrapper as an Echo Request to X or to a pool member with B as the source address. X answers with an Echo Reply to B, so the wrapper reaches the bridge from X. The table shows the Echo wrapper.

| Part | Size | Content |
| --- | ---: | --- |
| IPv4 header | 20 | The source is B and the destination is X, with protocol ICMP. The reflector swaps the addresses in its reply. |
| ICMP header | 8 | Type 8 and code 0 for an Echo Request. The identifier is the port of the entry. If the path has a source range, the sequence is a random value of that range. Otherwise, it is the port of the entry. The checksum is valid for the whole ICMP message. |
| Bridge header | 12 | The same as in the UDP wrapper. |
| Inner header | 8 | The ICMP header of the reply, an Echo Reply from the bridge address, with no change. |
| Payload | n | The WireGuard message or the control frame, with no change. |

The reply inside an Echo wrapper always has a complete ICMP checksum, because the reflector checks the whole message. The reflector returns the same message with type 0, an Echo Reply. It keeps the identifier, the sequence, and the bytes after the ICMP header. The bridge takes the Echo Reply only from a sender that its entry allows. It then removes the 8-byte ICMP header and the bridge header, and it sends the reply to the client from its own address.

The bridge program handles each packet to an address of the bridge host and a port of the bridge:

1. A UDP payload, or an ICMP Echo Reply payload, that starts with the bridge magic is a wrapped reply. It must come from the server of the entry for its port, or from an `allow` range of that entry. A member that such a range holds also counts. Otherwise, the program counts reason 23. It must have version 1, UDP or ICMP inside, and a MUP packet inside, or the program counts reason 24. The program removes the wrapper and writes the inner protocol and addresses into the IPv4 header. The wrapper of an Echo Reply is its 8-byte ICMP header and the bridge header.
2. Any other MUP packet goes to the server of the entry for its port, except a packet from that server itself. A MUP packet is a control frame, or a WireGuard message with a token, in UDP or in an ICMP Echo Request.
3. Every other packet goes on to the kernel. So a normal ping to the bridge still gets its reply.

The program then finds the interface of the new destination with the FIB lookup of a forwarded packet, and it redirects the packet there. So the bridge host needs IPv4 forwarding.

## Packet flow

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".docs/images/packet-flow-dark.svg">
  <img alt="Sequence of one round trip between a WireGuard peer and the target" src=".docs/images/packet-flow-light.svg">
</picture>

One round trip has four legs. The value under each arrow shows WireGuard bytes 1 to 3 on that leg, and amber marks a peer token. The sections below give the steps of each leg in order.

### Client ingress

A peer sends a UDP packet to the listen port of a group. The client program then does these steps:

1. It makes sure that the packet is a valid WireGuard message with zero reserved bytes.
2. It looks up the token of the peer endpoint. A new peer gets a token from `free_peer_tokens`. If the source IP of the new peer already has 1024 routes, the program drops the packet and counts reason 21.
3. It picks one healthy path of the group. In repeater mode, it picks every healthy path of the group.
4. It writes the token and rewrites the headers for the path. If the path has a source range, the source port or the identifier is a random value of the range. An ICMP packet then also gets the path tag.
5. It sends the packet out of the path interface with `bpf_redirect_neigh`, which resolves the next hop.

In repeater mode, the program sends a clone on each healthy path of the group except the last one. For each clone, a FIB lookup gives the output interface and the MAC addresses. The original packet goes out on the last healthy path.

### Server ingress

A UDP packet arrives at a server port, or an ICMP Echo Request arrives with a server port as identifier. The server ports are one port or a range, for example 5000-6000. The server program then does these steps:

1. It looks up the registered path by source IP, local IP, port, and transport. A tagged Echo Request uses the tag in place of the port. The path gives the client key. If no path matches a UDP packet, the packet is not MUP traffic, and the program returns `TCX_NEXT`.
2. It makes sure that the packet is a valid WireGuard message with a token from 1 to 4095.
3. It makes sure that the path and the registration of the client exist and did not expire. An Echo Request without a registered path stops here, and a tagged one counts reason 8. If the program passed it, the kernel echoes the WireGuard message back to the client, for example before the ACK of a new client.
4. If the duplicate cache holds the same route and first 24 WireGuard bytes, it drops the packet.
5. It finds the route of the client key and token. For a new route, it takes a port from `free_target_ports`. For a target on the server host, it never takes the port of the target.
6. It records the path of this packet as the return path of the route. The route also keeps the source range of the path.
7. It clears the token and rewrites the packet to UDP, from the target port to the WireGuard target.
8. It sends the packet out of the interface that leads to the target.

Other traffic of the server host can use a port of the server range. For example, a NAT that masquerades a flow to a container can pick that port. The replies of the container then reach the server program on the container interface before conntrack restores their address. Step 1 leaves these packets to the kernel.

The duplicate cache keeps each entry for 2 seconds. The first 24 WireGuard bytes hold the message type, the token, the receiver index, and the counter for data messages. Two different packets of one peer thus never share an entry.

### Target reply

A UDP packet from the target address and port arrives at a target port. The server program then does these steps:

1. It finds the route by the destination port.
2. It makes sure that the message is valid WireGuard with zero reserved bytes.
3. It makes sure that the registration of the client is still live.
4. It writes the token and rewrites the headers for the return path of the route. If that path has a source range, the source port or the identifier is a random value of the range. An ICMP reply also gets the path tag.
5. It sends the packet out of the interface where the latest ingress packet of the route arrived.

### Ingress delivery

Ingress delivery (`target_ingress`) is for a target on the server host that has its own TC program on an interface. An example is a WireGuard router with an eBPF fast path. Without it, the server sends to a target on the server host through the loopback interface. A program on another interface then never sees the packets.

With ingress delivery, the target address must be an address of the server host on an Ethernet interface. The server changes two steps of the ingress flow:

1. It rewrites the packet from the advertised IP of the client and the target port of the route, not from its own address.
2. It injects the packet into the ingress hook of the interface that holds the target address. The Ethernet destination is the address of that interface.

The programs on that hook then see a packet from the client, and the kernel delivers it to the target. The target answers the advertised IP of the client, so the reply leaves through the egress hook of the same interface. There, `mup_server_egress` catches a UDP packet from the target address and port. The packet goes to the advertised IP of a route, at the target port of that route. It then does the target reply steps. If the reply leaves on the same interface, the program writes the Ethernet header from a FIB lookup and passes the packet on. Otherwise, it redirects the packet.

A program before `mup_server_egress` on the egress hook can rewrite the reply source to the target address, as a WireGuard router does. So `mup_server_egress` goes after the programs already on the hook at attach time. Such a program must attach at the head of the hook. The target port must be outside the server ports, because an injected packet passes the server program again.

If the target checksum offload is on, the reply has `CHECKSUM_PARTIAL`. The program detects this from the checksum field, which then holds only the pseudo-header sum, and uses the partial rewrites.

### Client egress

A packet with a nonzero token arrives at the advertised IP. The client program then does these steps:

1. It makes sure that a UDP packet goes to the listen port of a group.
2. It makes sure that an ICMP packet is an Echo Reply with the port of an ICMP path. For a tagged packet, it finds the path by the tag and makes sure that the identifier is in the range of the path.
3. It makes sure that the message is valid WireGuard with a token from 1 to 4095.
4. It finds the peer endpoint by the token. The listen port of the endpoint gives the group.
5. It makes sure that the source is an expected source for that group, as the return modes section describes.
6. It clears the token and rewrites the packet to UDP, from the listen address to the peer.
7. It sends the packet out of the interface where the traffic of the peer arrives.

## Path selection

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".docs/images/modes-dark.svg">
  <img alt="Failover, balancer, and repeater modes" src=".docs/images/modes-light.svg">
</picture>

Go writes the data set of each group, not the set of healthy paths. The client writes it to `path_state`, and the server writes it to `server_down_groups`. A data set holds the paths that carry data, as defined in [Usable paths and data sets](#usable-paths-and-data-sets). The rules of the three modes then apply inside the data set. Each healthy path in the rules below means a path of the data set. Room means that the bandwidth limit of a path accepts the packet. A path without a limit always has room. When no path of the data set has room, the program drops the packet and counts reason 26. See [Bandwidth limit](#bandwidth-limit).

The client program reads the data set mask from `path_state` for each packet. It keeps only the bits in the path mask of the group of the peer. The mode of the group then selects one of three rules:

- Failover: The program uses the healthy path with the lowest priority that has room. The priority is the position of the path in the configuration. A full path spills its packets to the next path in priority order.
- Balancer: The program computes a hash of the token and the mask, and uses it to pick one healthy path. If that path has no room, the program takes the other paths of the data set in the failover order. It uses the first one with room. With a limit on every path of the direction, the weights of [Bandwidth limit](#bandwidth-limit) apply.
- Repeater: The program sends the packet on every healthy path that has room.

The balancer hash is `h = token * 0x9e3779b1 ^ mask * 0x85ebca6b`, then `h ^= h >> 16`. The index of the path in the list of healthy paths is `h % count`. A peer thus stays on one path until the set of healthy paths in its group changes. A health change in another group does not move the peer.

Without egress paths, the server does not select paths. It replies on the path of the latest ingress packet of each route. After a failover, the first ingress packet on the new path moves the egress traffic too. In repeater mode, the first copy to arrive sets the return path. A route that arrived on an ingress path with `via` is the exception, because that path carries no replies. Without egress paths for its group, the server drops the reply and counts reason 15.

The server keeps the egress paths of each group apart, by the client key and the listen port. For a group with egress paths, the server picks the egress path of each reply from the healthy egress paths of the listen port of its route. The egress mode uses the rules of the client:

- Failover: The server uses the healthy egress path with the lowest ID that has room. A full path spills its replies to the next egress path in ID order.
- Balancer: The server hashes the token and the mask with the formula above. If that path has no room, the server takes the other paths of the data set in the failover order. It uses the first one with room.
- Repeater: The server sends the reply on every healthy egress path that has room.

In repeater mode, the client keeps the first copy of each message for 2 seconds and drops the other copies with reason 16. If the group has no healthy egress path on the server, the server drops the reply and counts reason 15.

With failover and `prefer: latency`, the data set is the usable set, and the chosen path comes first. On the client, Go writes the chosen path with priority 0, and the other paths follow in their configured order. On the server, the failover rule tries the preferred path in `server_down_groups` first, then the lowest ID. So a full chosen path can spill to the next path. A group without limits chooses the same path as before.

## Control plane

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".docs/images/control-plane-dark.svg">
  <img alt="The REGISTER and REGISTER_ACK exchange and the path health states" src=".docs/images/control-plane-light.svg">
</picture>

### Registration

The client registers each path on its own. It sends a REGISTER frame from `-s` to the server address of the path. A UDP path sends the frame in a UDP datagram to the server port. An ICMP path sends the frame as the payload of an Echo Request, with the port as identifier. The frame holds the listen port of the group and the return IP of the path. The TCX programs pass these frames to the kernel, and the Go control plane answers them.

A UDP path sends its REGISTER frames from the listen port of its group. For a path without a source range, the frames then have the same addresses and ports as the data of the path. So the control frames and the data share one UDP flow. A filter that blocks the data flow also blocks the REGISTER frames, and the path becomes unhealthy. A path with a source range sends its data from other ports, so its frames do not share the flow of the data. The UDP paths of one group share one control socket, which the client binds to `-s` and the listen port. If a path names an interface, its frames leave on that interface, and the client accepts an ACK only from that interface. An ICMP path has its own raw socket, and its control frames and data share the Echo identifier unless the path has a source range.

For each REGISTER, the server makes sure that all of these conditions are true:

- The source address of the packet equals the advertised IP in the frame.
- The port in the frame is a server port, and the frame arrived on that port.
- The transport in the frame equals the transport that carried the frame.
- The path ID is from 0 to 7.

The server then writes the registration to `registration_by_key` and the path to `registered_paths`. Both entries get a lease of 30 seconds. The server answers with a REGISTER_ACK frame from the address that received the REGISTER. The ACK repeats the frame with the type REGISTER_ACK, the status 0, and a lease of 30 seconds. If a condition is false, the server sends no reply.

The client waits 900 milliseconds for an ACK with the same nonce, path ID, and sequence. After an ACK, it sends the next REGISTER in 10 seconds. After a missing ACK, it sends the next REGISTER in 1 second. The source port of the REGISTER frames of a UDP path never changes, because it must stay the listen port.

A REGISTER of a path with a source range has flag bit 7 and the first and last value of the range. The server writes the range to `registered_paths`. For an ICMP path, it also writes an entry with the path tag, which is the path slot plus 1.

### Egress path registration

An ingress path of a group with egress paths sends one EGRESS_REGISTER frame for each egress path of the group before each REGISTER. The frames travel like the REGISTER, so each server that an ingress path reaches gets all of them. The server applies the REGISTER rules to the source, the port, and the path ID. It keeps only an egress path whose server address is an address of the server host. An egress path has a lease of 30 seconds, in bits 0 to 7 of the lease field. A EGRESS_REGISTER with a whole lease field of zero withdraws an egress path that `mupctl` removed.

A EGRESS_REGISTER of an egress path with a source range has flag bit 7 and the first and last value of the range. The server writes the range to `server_down_paths`.

A EGRESS_REGISTER with flag bit 4 declares an egress bridge, and its egress server field holds the bridge address. A client does not know which server a bridge serves. So each server keeps an egress bridge without the address check and without the port check, and it probes the bridge.

A EGRESS_REGISTER with flag bits 4 and 6 declares an egress bridge with a via. The return IP field holds the via, or the base of the return pool, and it applies to the leg from the server to the bridge. A server before v0.5.0 refuses the frame.

The client sends an EGRESS_LIMIT frame right after each EGRESS_REGISTER of an egress path that has a limit. The frame has type 10. It has the same sender, path, and reflect handling as that EGRESS_REGISTER. The server accepts it under the same checks as an EGRESS_REGISTER, and only for an egress path that it keeps. The server keeps the limit with the path. When 3 EGRESS_REGISTER frames arrive in a row with no EGRESS_LIMIT after them, the server removes the limit. An EGRESS_LIMIT with a rate of zero also removes the limit. An older server drops the frame without a reply and applies no limit.

The server sends each REGISTER_ACK directly, and also on every egress path of the client, with the next member of a pool each time. One ACK makes the ingress path healthy, on any of these ways. So an ingress path stays healthy, even with no packet back on its own flow.

### Ingress reflect registration

An ingress reflect path sends its REGISTER reflected through each member. The frame has flag bit 5 and the member as the return IP. On an ICMP path, the client sends an Echo Request to the member, with the server as the source. The member then answers the server with an Echo Reply. On a UDP path, the client sends to the server with the member as the source. The server reads the reflected source as the path source, not the advertised IP. It registers one path for each member, and skips the reflector setup of a reply pool. The ACK of each member names the member in its return IP. So the client knows the members that answer. It keeps a member until the member misses 3 rounds in a row, and an answer brings the member back. While a kept member has a miss, the next round comes after 1 second. The client keeps the members in the order of the pool, so a peer in the per-peer mode stays on its member. The members that answer carry the ingress, as `up_reflect_members` on the client and one registered path for each member on the server.

An ingress reflect path without a bridge also reflects the other control frames of its group. These frames are each EGRESS_REGISTER and each PROBE_REPLY of an egress path. The client sends a EGRESS_REGISTER through every member that answered the latest REGISTER. While no member answered, it sends the frame through every member. It sends a PROBE_REPLY through one of these members in turn. The server accepts such a frame from the advertised IP. It also accepts the frame on a registered ingress reflect path of the same client key. On the first cycle of a new client, the EGRESS_REGISTER arrives before the path exists. The server refuses it, and the retry after 1 second passes. This needs a server of v0.4.7 or later.

### Client restarts

A client picks a new instance nonce at each start. The server keeps one registration for each advertised IP. A REGISTER with a new nonce replaces the registration of the old nonce. The next sweep then deletes the paths and routes of the old nonce.

### Control frame

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".docs/images/control-frame-dark.svg">
  <img alt="The 48-byte layout of the control frame" src=".docs/images/control-frame-light.svg">
</picture>

The control frame is 48 bytes long, and all integers are big-endian.

| Offset | Size | Field | Value |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | 0x4d555043, which is "MUPC" in ASCII. |
| 4 | 1 | version | 1. |
| 5 | 1 | type | 1 is REGISTER, 2 is REGISTER_ACK, 3 is PROBE, 4 is PROBE_REPLY, 7 is EGRESS_REGISTER, 8 is MEASURE, 9 is MEASURE_REPLY, and 10 is EGRESS_LIMIT. Type 5 and type 6 are reserved. |
| 6 | 1 | transport | 0 is UDP and 1 is ICMP. |
| 7 | 1 | flags | Bit 0 means that the return IP field holds one return IP. Bit 1 means that it holds the base of a return pool. Bit 2 selects the per-packet balance mode of a pool. Bit 3 marks a PROBE or a PROBE_REPLY of an egress path, and its path ID is then an egress path ID. Bit 4 marks a EGRESS_REGISTER of an egress bridge. Bit 6 marks a EGRESS_REGISTER of an egress bridge whose return IP or pool applies to the leg from the server to the bridge. Bit 6 needs bit 4 and bit 0 or bit 1. Bit 5 marks a REGISTER or a MEASURE whose return IP is the via of an ingress reflect path. Bit 7 marks a REGISTER or a EGRESS_REGISTER of a path with a source range. The other bits must be zero. |
| 8 | 2 | length | 48. |
| 10 | 2 | status | 0 is OK. 7 is NO_REFLECTOR: the return pool of the path has no healthy reflector. Values 1 to 6 name errors, but the server does not send them. |
| 12 | 2 | path ID | 0 to 7, the slot of the path in the client. |
| 14 | 2 | listen port | The listen port of the group of the path. |
| 16 | 2 | server port | The server port. |
| 18 | 1 | egress mode | In a EGRESS_REGISTER, the egress mode: 0 is failover, 1 is balancer, and 2 is repeater. Zero otherwise. |
| 19 | 1 | pool prefix | The prefix length of the return pool, 1 to 31, with flag bit 1. Zero otherwise. |
| 20 | 4 | advertised IP | The client `-s` address. |
| 24 | 4 | return IP | The return IP or the pool base of the path, or zero. In a PROBE_REPLY, the reflector that reached the client. |
| 28 | 8 | instance nonce | The nonzero random number of the client process. |
| 36 | 4 | sequence | A counter that goes up by one with each REGISTER on the path. A EGRESS_REGISTER does not use it. A MEASURE uses its own counter for each ingress path, and its MEASURE_REPLY copies it. With flag bit 7, it holds the range: the first value at offsets 36 and 37, and the last value at offsets 38 and 39. In an EGRESS_LIMIT, the rate in kilobits per second. |
| 40 | 4 | lease seconds or count code | In a REGISTER or a REGISTER_ACK, 30. In an EGRESS_REGISTER, bits 0 to 7 hold the lease, 30. Bit 8 is prefer latency, with 1 for latency and 0 for order. Bits 16 to 31 hold the loss tolerance in tenths of a percent, from 0 for none to 1000. A whole field of zero withdraws an egress path. A server before v0.5.4 tests the field only against zero, so it ignores the new bits. In a PROBE or a PROBE_REPLY of an egress path, the count code of the path, or zero. In a MEASURE or a MEASURE_REPLY, the count code of the packets that the client sent on the ingress path. In an EGRESS_LIMIT, the flags. Bit 0 means per-member, and the other bits are zero. |
| 44 | 4 | egress server | In a EGRESS_REGISTER, the server address of the egress path, or the bridge address with flag bit 4. A REGISTER does not use it. In a MEASURE_REPLY, it holds the count code of the packets that the server received on the ingress path. In a MEASURE, it is zero. With flag bit 7, it holds the range: the first value at offsets 44 and 45, and the last value at offsets 46 and 47. In an EGRESS_LIMIT, zero. Zero otherwise. |

Some payloads are exactly 48 bytes long and start with the magic, version 1, and length 48. The TCX programs pass such a payload to the kernel as a control frame.

## Path health

The client measures the health of each path with the ACKs to its REGISTER frames. A path from the flags or the configuration file starts healthy. A path that `mupctl` adds starts unhealthy. Three missed ACKs in a row make a path unhealthy, and one ACK makes it healthy again. Each change increases the generation. Go writes the mask of healthy paths and the generation to `path_state`.

A dead path becomes unhealthy about 5 to 15 seconds after it fails. The delay depends on the time that remains until the next REGISTER. If no path of a group is healthy, the client drops the ingress packets of that group and counts reason 15.

### Egress path health

Every 2 seconds, the server sends a PROBE on each egress path of each client, in the same way as a reply. A path with a pool gets one probe through each member. The client answers each probe with a PROBE_REPLY on its healthy ingress path with the lowest priority. The reply travels like the REGISTER of that path. If no ingress path is healthy, it answers on every ingress path. The reply names the source of the probe, which is the member of a pool. On a path with flag bit 6, the client sees only the bridge address as the source. So the PROBE names its member in the return IP field, with flag bit 0, and the client copies that member into the PROBE_REPLY.

An egress path, or a member of its pool, is healthy for 6 seconds after its latest reply. A new egress path is healthy for its first 6 seconds. A new egress bridge is unhealthy until its first reply, because the bridge drops the wrapped probes of servers that it does not allow. The members of a pool come from the sweeps of the pool, but each egress path keeps its own member health. So a member that answers the ping of the server but does not reach the client carries no replies of that client.

The client shows an egress path as healthy while its probes arrive. It shows an egress path as in use while the program accepts replies on it.

### Port moves

A path can have a range of server ports. A filter on the way can drop the packets of one flow and pass the others. So a path that gets no ACK on one server port can get through on another. The path starts on the first port of its range. If 10 REGISTER frames in a row get no answer, the client moves the path to a random other port of the range. With the ACK timeout and the retry of 1 second, the first move comes about 19 seconds after the last answer. Each move without an answer doubles the number of frames before the next move, up to 160. An ACK or a NO_REFLECTOR answer resets the count to 10, and a NO_REFLECTOR answer never moves a path, because the server received the frame.

The client moves a path in this order:

1. It opens the control socket of the path on the new port. A UDP path joins the control socket of its group again, so the socket stays open.
2. It writes the new port to `path_config`.
3. It stops the REGISTER loop of the old port and starts the loop of the new port.

The path stays unhealthy until the first ACK on the new port. A result from the loop of the old port has no effect on the moved path. The server needs no change, because it learns the new port from the REGISTER frames. Each server route takes the new port with the next ingress packet of its peer. The registration of the old port ends with its lease after 30 seconds. The client does not save a move, so the path starts on the first port again at the next start.

## Path measurement

The client and the server measure the loss and the round trip time of each path. The measurement changes no path choice and no path health. It uses the counts of the data packets, and small control frames for the probe values.

### Count code

A count is the number of data packets that a path carries. A control frame carries the count as a 32-bit code. The sender computes the code as `code = count mod 0xFFFFFFFF + 1`. Code 0 means no count, and an older peer sends it. The difference of two codes is taken modulo 0xFFFFFFFF.

### Counter maps

Each side counts the data packets of its paths in two per-CPU maps. Each entry holds a packet count and a byte count. The byte count is the IPv4 total length of the packet at the count point. When Go reads an entry, it sums the CPUs.

`client_path_counters` is an array of 16 entries. Index 0 to 7 counts the data packets that the client sends on each ingress path slot. Index 8 plus j counts the data packets that the client accepts from egress path j.

`server_path_counters` is a hash of 8192 entries. Its key holds the client key, a path ID, and a direction. Direction 0 counts the data packets that the server receives from the client on an ingress path. Direction 1 counts the data packets that the server sends to the client on an egress path. The BPF programs add only to an entry that exists. Go creates an entry for each registered path, and it deletes the entry of each path or client that goes away.

The programs count only data packets. They count before a later drop, such as the duplicate check of the repeater mode. The four count points are:

1. The client counts each ingress send, once for each path that gets a copy. It counts after the path selection and the rewrite.
2. The client counts each egress receive, where it accepts a data packet from an egress path.
3. The server counts each ingress receive, right after the lookup in `registered_paths`. All members of an ingress reflect path count into one path ID.
4. The server counts each egress send, once for each copy, in `down_send_core`. It counts after the rewrite and the wrap succeed.

### Ingress measurement

The client sends one MEASURE on each ingress path every 2 seconds. It sends the frame on every path, healthy or not. On an ingress reflect path, it sends one MEASURE through each member. The server answers each MEASURE with a MEASURE_REPLY, and the client takes an RTT sample from it.

A MEASURE has type 8. Offsets 0 to 35 have the layout of a REGISTER. Its flags are zero, or bits 0 and 5 on an ingress reflect path, with the member in the return IP field. Offset 36 holds the sequence of the frame, and each ingress path has its own counter. Offset 40 holds the count code of the packets that the client sent on the ingress path. Offset 44 is zero.

A MEASURE_REPLY has type 9. It copies the MEASURE and changes the type to 9. Offset 44 holds the count code of the packets that the server received on the ingress path. The server reads that count on arrival of the MEASURE.

The server handles a MEASURE in the same way as a REGISTER. It makes the same checks of the source, the port, the transport, and the path ID. It accepts a MEASURE on a registered ingress reflect path, as it does for a REGISTER. It answers only for a registered client key and path. It creates and refreshes nothing. It sends the MEASURE_REPLY as it sends a REGISTER_ACK: to the source, and once on every egress path of the client.

The client accepts a MEASURE_REPLY on the socket of the path, and on an egress path, as it accepts a REGISTER_ACK. It takes an RTT sample for each egress path from the MEASURE_REPLY that arrives there, as it does from a REGISTER round.

A decoder must accept offset 44 for type 9. It must require zero at offset 44 for type 8, and it must allow no other flag on these types.

### Egress measurement

The server sends a PROBE on each egress path every 2 seconds, as described in [Egress path health](#egress-path-health). The lease field of the PROBE holds the count code of the packets that the server sent on that path. The server reads the count just before the send. All probes of one round for one path carry the same value. The client answers with a PROBE_REPLY. Its lease field holds the count code of the packets that the client accepted from that path. The client reads that count on arrival of the PROBE.

### Loss trackers

Each side keeps a loss tracker for each path that it measures. A loss tracker stores markers. A marker holds a sender count and a receiver count from the same moment. These frames give the counts:

| Path | Side | Sender count | Receiver count |
| --- | --- | --- | --- |
| Ingress | Client | Count in the MEASURE | Count in the MEASURE_REPLY |
| Egress | Server | Count in the PROBE | Count in the PROBE_REPLY |
| Egress | Client | Count in the PROBE | Own count, read on arrival of the PROBE |

The tracker takes the newest marker, and the oldest marker that is not older than the window. The window is 10 seconds or 60 seconds. The tracker gives a value only for two markers that are at least half a window apart.

The tracker computes `dtx` and `drx`, the differences of the sender count and the receiver count between these two markers, modulo 0xFFFFFFFF. The loss is `max(0, 1 - drx / dtx) * 100`, in percent. If `dtx` is below 50 packets, the tracker gives no value.

If a marker goes back, with a difference of 2^31 or more, the tracker ignores the marker. Three such markers in a row mean that a counter started again from zero, and the tracker then starts from the newest marker. If `drx` is larger than `dtx + max(64, dtx / 4)`, the peer started its counts again. The tracker then drops the older markers and starts from the new marker.

### Probe trackers

The server keeps a probe tracker for each member of each egress path. The client keeps one for each ingress path, and for each member of an ingress reflect path. A probe is complete after its answer arrives, or 2 seconds after it was sent. A second answer to the same probe counts once, with the time of the first answer.

The probe loss is the share of the complete probes of the last 60 seconds that get no answer. It has no value until one answer arrives and 5 probes are complete. The average RTT is the mean RTT of the answers in the last 60 seconds. The jitter is the mean of the absolute difference between each RTT and the RTT before it, over the same 60 seconds.

### Rate trackers

The rate is the number of packets and bits per second of a counter over the last 10 seconds. The bits come from the byte counts. The client samples each ingress counter on each tick. The server samples each egress counter on each probe round.

### Compatibility

The change keeps every existing map layout and frame layout. It changes no path selection. These rules apply to mixed versions:

- A peer that sends code 0, or no MEASURE_REPLY, gives no loss value. The loss field stays empty. It is never zero, and it is never 100 percent.
- A new client with an old server gets no MEASURE_REPLY. The measurement fields of the ingress paths stay empty.
- An old client with a new server ignores the count in the PROBE lease field. Its PROBE_REPLY holds code 0, so the egress data loss stays empty.
- An older decoder refuses each type above 7. It drops the frame without a reply.
- A bridge passes every 48-byte control frame, so it needs no change.

## Loss tolerance and latency choice

The client and the server act on the loss and RTT values of [Path measurement](#path-measurement). Each group direction has two keys. `tolerance` is the loss tolerance, and `prefer` selects the latency choice of the failover mode. Without the keys, every decision works as in v0.5.3.

### Usable paths and data sets

A usable path is healthy and not degraded. If no path of a group direction is usable, every healthy path counts as usable. The data set of a group direction holds the paths that carry data.

The data set is the usable set in every case. With failover and `prefer: latency`, the path that the latency chooser returns comes first in the failover order. The rule of the mode then picks a path inside the data set. Failover takes the first path with room in the failover order, balancer takes the hash, and repeater takes every path with room.

### Loss gate

The loss gate decides whether one path is degraded. Each path has its own gate, and each pool member has one too. On each evaluation, the gate reads the loss tolerance, the evidence, and the time. Its output is the degraded state and a reason.

For a path with a data loss value, the evidence is the data loss over the 10 second window. Otherwise, the evidence is the probe loss.

- A path that is not degraded becomes degraded with evidence above the tolerance.
- For a degraded path, recovery needs two conditions. Its time in the degraded state is at least the hold. Its evidence is at most half the tolerance.
- A path without evidence keeps its state.
- The hold is the minimum time that a path stays degraded. Each degradation gets a strike number. A degradation within 10 minutes after the last recovery adds one to the number. Otherwise the number starts again at one.
- The hold is 30 seconds at strike one. It doubles with each strike, up to 10 minutes.
- A tolerance of zero means none. The gate then never degrades a path, and a degraded path recovers at once.
- The reason names the evidence. For example, `loss 12.5% above 5%` or `probe loss 12.5% above 5%`.

### Pool members

A pool member uses the same gate, with its probe loss as the only evidence. A member that is degraded leaves the member list of its path. If every healthy member of a path is degraded, all healthy members stay in the list.

### Latency chooser

The latency chooser picks the path of a failover group direction that has `prefer: latency`. For each path, it gets the ID, the priority, the usable state, and the average RTT. The average RTT counts with at least 5 samples in its 60 second window. An RTT of zero means unknown.

- With no current path, or an unusable current path, the chooser takes the usable path with the lowest known RTT at once. Paths without a known RTT rank after all others, by priority.
- Otherwise, the chooser keeps the current path. A better path is a usable path whose RTT is lower than the current RTT by more than the margin. The margin is the larger of 10 percent of the current RTT and 2 milliseconds.
- A better path must stay the best such candidate for 10 seconds without a break before the chooser switches to it.
- A current path with an unknown RTT counts as worse than every known RTT. The same 10 second rule applies to it.

The constants are `latencyMargin` of 0.10, `latencyMarginFloor` of 2 milliseconds, and `latencySwitchAfter` of 10 seconds.

### Where each side applies the result

- The client writes the union of the data sets of all its ingress group directions as the mask of `path_state`. Health does not change. The generation changes only with a change of the mask.
- The client writes the members that are not degraded to `up_reflect_members` for each ingress reflect path.
- The server writes the data set of each group to the healthy mask of `server_down_groups`, for that group.
- The server writes the members that are not degraded to the member list of each egress path.
- Each side uses the RTT that it measures for its own paths.

### Evaluation times

The client evaluates the gates and the chooser on each measurement tick, every 2 seconds, and on each health change. The server evaluates them on each probe round, every 2 seconds, and on each registration.

### Egress keys on the wire

The client sends both egress keys in each EGRESS_REGISTER of the group, in the lease field. All paths of one group carry the same keys. The server takes the keys of a group from the latest frame, as it does for the egress mode.

### Mixed versions

- A gate without evidence never degrades a path. An older server gives no loss counts, so the ingress paths of a client keep their state.
- A server before v0.5.4 keeps its egress paths and ignores the keys. It has no gate and no latency choice for them.
- The latency chooser needs only the RTT of the local side, so it works with any peer.
- A bridge passes these control frames, so it needs no change.

## Bandwidth limit

A path with `bw RATE` has a bandwidth limit. The client applies it to the ingress paths, and the server applies it to the egress paths. Each limit is a GCRA bucket. GCRA is a token bucket in virtual scheduling form. Its state is one 64-bit time, so the decision needs no lock.

Go computes two values for each limit:

- `cost_q16` is the time for one byte, in nanoseconds, in 48.16 fixed point. It is `(8e9 / rate_bps) * 65536`.
- `burst_ns` is the larger of 50 milliseconds and the time for 3000 bytes.

The state is `tat_ns`, the theoretical arrival time. All CPUs share it.

For a packet of `bytes` bytes at time `now`, the program does these steps:

1. It sets `start` to the larger of `now` and `tat_ns`.
2. It sets `new` to `start + ((bytes * cost_q16) >> 16)`.
3. If `new - now` is at most `burst_ns`, the packet has room.
4. If the packet has room, it writes `new` with one compare and swap against the value that it read. If another CPU changed the value in between, the swap fails. The packet then has room without a write, so the limit lets a little more pass in that case.

So a path sends a burst of about 50 milliseconds of its rate, and then sends at its rate. Below 480 kbit per second, the burst is the time of 3000 bytes.

A packet costs its IPv4 total length in bytes. A path that wraps the packet for a bridge adds 20 bytes to that cost. Control frames do not count against the bucket, and the limit never drops them.

The decision is made once per packet per path, before the rewrite. A packet that the program then cannot send for another reason still counts against the bucket.

### Buckets

The client keeps one bucket for each ingress path slot. It keeps one bucket for each member of a per-member path. The server keeps one bucket for each egress path, and one bucket for each member of a per-member path. When a path slot gets a new path, its bucket starts again. A path with a pool and a plain RATE uses one bucket for the path, and its member choice does not change.

### Per-member limits

A packet on a per-member path starts with the member that the normal choice gives. That choice is the per-packet cursor or the per-peer hash. If that member has no room, the program tries the next members of the published list in order. A path with no member that has room has no room.

### Weights

When every path of a group direction has a limit, Go gives each path a weight that follows its RATE. Go then normalizes the weights of the direction. The balancer picks a path in proportion to the weights. A path with twice the rate gets about twice the peers. Otherwise, every path has the same weight, as before.

### Compatibility

Without `bw`, every decision and every map content that matters equals v0.5.4. An ingress limit needs only a v0.5.5 client. An egress limit needs a v0.5.5 client and server. An older server drops EGRESS_LIMIT and applies no limit. A bridge needs no change.

## Dataplane state

Pinned BPF maps hold all dataplane state. Go writes the configuration and the registrations. The programs create routes, and Go expires them.

| Map | Type | Capacity | Key and value | Writer |
| --- | --- | ---: | --- | --- |
| `client_config` | array | 1 | Nonce, `-s`, and generation. | Go |
| `path_groups` | hash | 8 | Listen port to mode, path mask, egress path mask, and flags. Flag bit 0 turns on the duplicate filter of the egress repeater mode. The return IP field is not used. | Go |
| `path_config` | array | 8 | Destination, source, interface, port, transport, and priority of each path. | Go |
| `path_returns` | array | 8 | Return IP and flags of each path. | Go |
| `client_path_src` | array | 8 | The first and last value of the source range of each path slot. A first of 0 means none. | Go |
| `path_state` | array | 1 | Healthy mask and generation. | Go |
| `client_down_paths` | array | 8 | Server, return IP or pool, port, and transport of each egress path, and the time of its latest reply. | Both |
| `client_down_src` | array | 8 | The first and last value of the source range of each egress path slot. A first of 0 means none. | Go |
| `client_path_counters` | per-CPU array | 16 | Data packet and byte counts of each ingress path slot, and of each egress path. | Program |
| `server_path_counters` | per-CPU hash | 8192 | Client key, path ID, and direction to the data packet and byte counts of the path. | Both |
| `client_duplicate_cache` | LRU hash | 16384 | Token and first 24 WireGuard bytes to the time seen, for the egress repeater mode. | Program |
| `client_peer_by_endpoint` | hash | 4096 | Peer endpoint to token and last-seen time. | Program |
| `client_endpoint_by_token` | hash | 4096 | Token to peer endpoint, interface, and last-seen time. | Program |
| `free_peer_tokens` | queue | 4095 | Unused tokens. | Both |
| `client_routes_by_source` | hash | 4096 | Peer source IP to the number of its routes. | Both |
| `server_config` | array | 1 | Target, source IP, interface, and the first server port. | Go |
| `server_ports` | array | 1 | The first and the last server port. Without this entry, the server accepts only the port in `server_config`. | Go |
| `registration_by_key` | hash | 4096 | Client key to lease end and listen port, with the return IP and flags of the latest REGISTER. The programs do not read the return IP. | Go |
| `registered_paths` | hash | 32768 | Source IP, local IP, port, transport, and path tag to client key, return IP, flags, source range, and server port. | Go |
| `server_route_by_key` | hash | 41000 | Client key and token to target port, return path, and the source range of the return path. | Program |
| `server_route_by_port` | hash | 41000 | Target port to route key, return path, and the source range of the return path. | Program |
| `free_target_ports` | queue | 41000 | Unused target ports. | Both |
| `duplicate_cache` | LRU hash | 16384 | Route key and first 24 WireGuard bytes to the time seen. | Program |
| `server_down_groups` | hash | 4096 | Client key to listen port, egress mode, and the masks of its egress paths. | Go |
| `server_down_paths` | hash | 32768 | Client key and egress path ID to the egress path, its interface, its source range, and its healthy pool members. An egress bridge also has flag bit 4 and the source address of its wrapper. | Go |
| `bridge_config` | array | 8 | The entries of a bridge: the server, and the first and last port of each. An entry with a zero server is unused. | Go |
| `bridge_addresses` | hash | 64 | The IPv4 addresses of the bridge host. Go writes them again every 10 seconds. | Go |
| `bridge_allow` | LPM trie | 512 | The senders of wrapped replies, for each entry. The key starts with the entry index, then the sender address. | Go |
| `bridge_counters` | per-CPU array | 4 | The packets and bytes that a bridge sent ingress and egress. | Program |
| `stats` | per-CPU array | 26 | Drop counters, one for each reason. | Program |
| `events` | ring buffer | 256 KiB | Events for reasons 11, 12, and 13. | Program |
| `event_limits` | array | 26 | Rate limit of the events for each reason. | Program |

Each route has a forward entry and a reverse entry that point at each other. The program writes the forward entry first. If the reverse entry fails, the program deletes the forward entry and returns the token or port to its queue. The last-seen times in the maps use the monotonic clock of the kernel.

## Lifetimes and cleanup

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".docs/images/lifetimes-dark.svg">
  <img alt="The lifecycle of tokens and ports" src=".docs/images/lifetimes-light.svg">
</picture>

Go runs a sweep once per second. The sweep does these steps in order:

1. It repairs broken pairs of forward and reverse entries, and quarantines their tokens and ports.
2. It deletes expired registrations, and the paths of expired or replaced registrations.
3. It deletes client routes that had no traffic for 180 seconds.
4. It writes the exact number of routes of each peer source IP to `client_routes_by_source`.
5. It deletes server routes that had no traffic for 180 seconds, and the routes of deleted registrations.
6. It returns the tokens and ports with an ended quarantine to their queues.

The client program only adds to the counts in `client_routes_by_source`, so step 4 takes the expired routes off. In step 6, a value that a route owns again stays out of the queue. The expiry of that route puts the value into quarantine again. The quarantine of 120 seconds keeps a late packet of an old route away from a new peer.

The sweep copies each map before it deletes entries, because a deletion restarts a map iteration. Before it deletes a route, it reads the route again. If the program refreshed the route in the meantime, the sweep keeps it.

| Timer | Value | Purpose |
| --- | ---: | --- |
| Registration refresh | 10 s | Time between REGISTER frames on a healthy path. |
| Registration retry | 1 s | Time before the next REGISTER after a missed ACK. |
| ACK timeout | 900 ms | Time that the client waits for a REGISTER_ACK. |
| Missed ACKs | 3 | Missed ACKs in a row that make a path unhealthy. |
| Port move | 10 to 160 | REGISTER frames in a row without an answer that move a path with a port range. |
| Registration lease | 30 s | Life of a registration without a new REGISTER. |
| Route idle timeout | 180 s | Life of a route without traffic. |
| Quarantine | 120 s | Wait before a token or port goes back into use. |
| Duplicate window | 2 s | Time in which the server drops a repeater copy, and the client drops an egress repeater copy. |
| Egress path probe | 2 s | Time between two probes of each egress path. |
| Path measurement | 2 s | Time between two MEASURE frames on each ingress path. |
| Egress path health | 6 s | Life of the health of an egress path or a pool member without a probe reply. |
| Sweep | 1 s | Time between two sweeps. |

## Input rules

A network device can keep only the first bytes of a large packet in the buffer that a program can read. The programs need only the first 90 bytes of a packet: the headers, the start of the WireGuard message, and a control frame. If fewer bytes are readable, the program pulls them into the buffer. Only a checksum that MUP must compute makes it read the rest of the payload. It copies those bytes chunk by chunk without a pull.

The programs forward only IPv4 packets with a 20-byte header, no fragments, and a UDP or ICMP header. The UDP length must match the IPv4 total length. The WireGuard message must have a valid length for its type.

| Type | Message | Length in bytes |
| ---: | --- | --- |
| 1 | Handshake initiation | 148 |
| 2 | Handshake response | 92 |
| 3 | Cookie reply | 64 |
| 4 | Transport data | 32 or more. Senders usually pad to a multiple of 16, but some clients, for example Surge, do not. |

A program returns `TCX_NEXT` for traffic that it does not own. This traffic includes non-IPv4 packets, malformed IPv4 packets, other protocols, and packets to other ports. A program drops and counts a packet that is addressed to MUP but breaks a rule. An ICMP packet with an identifier other than the MUP port and without a path tag is not addressed to MUP. An ICMP packet with the MUP port as identifier but without a valid WireGuard message is the ping of another program. The program returns `TCX_NEXT` for it and does not count it.

## Drop reasons

| Reason | Name | Meaning |
| ---: | --- | --- |
| 1 | `MALFORMED_IPV4` | The IPv4 header is short, or its length is wrong. Only the repeater code counts it, after a clone. |
| 2 | `IPV4_OPTIONS` | The IPv4 header has options. Only the repeater code counts it, after a clone. |
| 3 | `IPV4_FRAGMENT` | The packet is a fragment. Only the repeater code counts it, after a clone. |
| 4 | `MALFORMED_L4` | The UDP or ICMP header is short, or the UDP length is wrong. Only the repeater code counts it, after a clone. |
| 5 | `WG_TYPE` | The WireGuard type is not 1 to 4. |
| 6 | `WG_LENGTH` | The WireGuard length does not match the type. |
| 7 | `WG_RESERVED` | The reserved bytes are not zero from WireGuard, or not a token from 1 to 4095 between MUP endpoints. |
| 8 | `NOT_REGISTERED` | The server has no live registration for the path or the client. A UDP packet without a registered path goes on to the kernel and counts no drop. A tagged ICMP WireGuard message without a registered path counts this reason. |
| 9 | `PATH_MISMATCH` | Reserved. Version 1 does not count it. |
| 10 | `TRANSPORT` | A path or a route has an unknown transport. |
| 11 | `PEER_TOKEN_POOL` | The client has no free token. |
| 12 | `TARGET_PORT_POOL` | The server has no free target port. |
| 13 | `MAP_INVARIANT` | A forward entry and its reverse entry disagree, or a map update failed. |
| 14 | `ROUTE_MISS` | The server has no route for the target port, or the client has no peer for the token. |
| 15 | `NO_PATH` | The group of the peer has no healthy path, or the group has no healthy egress path on the server. |
| 16 | `DUPLICATE` | The server already forwarded this repeater copy, or the client already passed this egress repeater copy. |
| 17 | `FIB` | A repeater clone got no FIB result for its path. MUP skips the clone, not the packet. |
| 18 | `NEIGHBOR` | A repeater clone failed to redirect. MUP skips the clone, not the packet. |
| 19 | `TAIL_CALL` | Reserved. Version 1 does not count it. |
| 20 | `CHECKSUM` | A rewrite failed, for example on a UDP packet without a checksum and with a payload longer than 9216 bytes. |
| 21 | `SOURCE_LIMIT` | The source IP of a new peer already has 1024 routes on the client. |
| 22 | `EGRESS_SOURCE` | An egress packet came from a source that the group of the peer does not expect. |
| 23 | `BRIDGE_SOURCE` | A bridge got a wrapped reply from a sender that is neither the entry server nor in its `allow` range. |
| 24 | `BRIDGE_PACKET` | A bridge got a wrapped reply with a bad version, a bad inner protocol, or no MUP packet inside. If a wrap or an unwrap fails half way, a server also counts it. |
| 25 | `BRIDGE_SIZE` | A reply for an egress bridge does not fit the MTU of the interface to the bridge after the wrap. |
| 26 | `RATE_LIMIT` | No path of the group has room under its bandwidth limit, so the packet is dropped. |

## Attachment and restarts

The loader pins the maps by name under `/sys/fs/bpf/mup/client`, `/sys/fs/bpf/mup/server`, or `/sys/fs/bpf/mup/bridge`. A bridge attaches to every Ethernet interface that is up. It pins each TCX link under `/sys/fs/bpf/mup/<role>/<role>/<ifindex>/ingress`. With ingress delivery, the server also pins the egress link of the target interface under `/sys/fs/bpf/mup/server/server/<ifindex>/egress`. Without it, the server removes that link at start. The client attaches to every Ethernet interface that is up and to the interface of each path. The server attaches to every Ethernet interface that is up and to the interface that leads to the target.

The programs read an Ethernet header from every packet. So MUP does not attach to an interface without one, for example a PPP, tun, WireGuard, or raw-IP modem interface. If a path or the target route uses such an interface, the start fails with an error.

At start, the loader does these steps in order:

1. It loads the programs with the pinned maps, or it creates and pins new maps.
2. It repairs broken pairs of forward and reverse entries.
3. It writes the number of routes of each peer source IP.
4. For a new queue, it fills the queue with every token or port.
5. For an existing queue, it puts each lost token or port into quarantine.
6. It deletes the groups that are not in the configuration, and it writes the configuration of the role.
7. It replaces the program in each pinned link, or it attaches and pins a new link.

Before step 1, the loader removes the pin of a map whose layout changed in this version. It does this only for the maps of counters and of state that the daemon or its clients write again soon after a start. v0.4.0 grew `stats`, `event_limits`, and `server_down_paths`, and v0.4.1 grew `path_config`. The client writes every slot of `path_config` at each start, so it loses no state. The program that is still attached keeps its old map until step 7 replaces it. The two path counter maps, `client_path_counters` and `server_path_counters`, are in the loader's rebuild list. Their content can be lost at a start, and their counts then start again from zero.

Every other pinned map must keep its layout, because the BPF library refuses a pin with another layout, and the start fails. v0.4.1 grew `path_config` without this step, so v0.4.1 does not start over the pins of an earlier version. The test `TestChangedPinsAreRebuilt` compares the maps with the layouts of each release in `dataplane/testdata/released_maps.json`. After a new tag, add its layouts with `go test ./dataplane -run TestChangedPinsAreRebuilt -record-release vX.Y.Z`.

A lost token or port is not free, not in a route, and not in quarantine. A crash between a pop and a route insert can lose one. Step 7 keeps forwarding active during a restart.

For a target on the server host, step 6 also deletes a route that owns the port of the target. Such a route can exist from a version that did not skip this port.

The TCX links stay attached after the process stops. The programs then forward with the last state, and routes no longer expire. The server programs still stop a client at the end of its lease, because they compare the lease end with the clock. To remove MUP from a host, stop the process and delete the pin directory of the role.

## Observability

The daemon does not log counters. The control socket reports them on demand, and `mupctl status` shows them. The table lists the source of each value.

| Value | Role | Source |
| --- | --- | --- |
| Drops | Both | The `stats` map, summed over all CPUs. |
| Paths | Client | The healthy mask and the generation in `path_state`. |
| Egress paths | Client | The time of the latest probe of each egress path, and the reply times in `client_down_paths`. |
| Peers | Client | The entries in `client_peer_by_endpoint`. The local port of an entry gives its group. |
| Tokens | Client | The used tokens and the quota of 4095. The used tokens are the routes and the tokens in quarantine. |
| Clients | Server | The entries in `registration_by_key` and `registered_paths`, and the egress paths with their health. |
| Peers | Server | The entries in `server_route_by_key`. |
| Target ports | Server | 41000, minus the routes, minus the ports in quarantine. |
| Duplicates | Server | The entries in `duplicate_cache`. |

The programs write events to the `events` ring buffer for reasons 11, 12, and 13. Each reason writes at most 10 events per minute. Go logs each event with the reason, the interface index, and the monotonic time. The logs never contain payloads or peer addresses.

## Control socket

The daemon serves a control API for `mupctl` on a Unix socket. The default socket is `/run/mup/client.sock` for a client, `/run/mup/server.sock` for a server, and `/run/mup/bridge.sock` for a bridge. A bridge serves only `GET /v1/status` and `DELETE /v1/drops`. The daemon creates the socket at each start with mode 0660. It replaces a stale socket file. If another daemon still answers on the socket, the start fails.

The API is JSON over HTTP/1.1. The file `api/api.go` defines the request and response types.

| Method | Path | Role | Result |
| --- | --- | --- | --- |
| `GET` | `/v1/status` | All | The overview and the drop counters. A bridge also shows its packet and byte counters. |
| `GET` | `/v1/paths` | Client | The paths with their health. |
| `POST` | `/v1/paths` | Client | Adds a path. The body is `{"path": "SERVER[%IFACE]:PORT/udp", "listen_port": 51820}`. With `"egress": true`, it adds an egress path. With `"bridge": true`, the path goes through the bridge that it names. |
| `DELETE` | `/v1/paths/{id}` | Client | Removes a path. With `?direction=egress`, it removes an egress path. |
| `PUT` | `/v1/mode` | Client | Changes the mode of a group. The body is `{"mode": "repeater", "listen_port": 51820}`. With `"egress": true`, it changes the egress mode. |
| `GET` | `/v1/peers` | Both | The peers of a client, or the peer routes of a server. |
| `GET` | `/v1/clients` | Server | The registered clients with their paths. |
| `GET` | `/v1/reflectors` | Server | The members of the return pools and their health. |
| `DELETE` | `/v1/drops` | All | Sets every drop counter to zero, on every CPU. |

The `listen_port` field selects a group. A client with one group does not need it. The status response of a client lists its groups.

A failed request returns a JSON object with an `error` field. The status is 400 for an invalid request and 404 for an unknown path ID or group. It is 409 for a request that the role or the current state does not allow, and 500 for a failure in the dataplane.

### Runtime path changes

A client has eight path slots. The slot number is the path ID in REGISTER frames, the bit in the healthy mask, and the index in `path_config`. A new path takes the lowest free slot and the next free priority. In failover mode, a new path thus comes after the existing paths of its group. The groups do not change while the daemon runs.

The client adds a path in this order:

1. It joins the path to the UDP control socket of its group, or it opens the raw socket of an ICMP path.
2. It attaches the client program to a new interface of the path.
3. It writes the path to `path_config`.
4. It adds the slot to the path mask of the group in `path_groups`.
5. It starts the REGISTER loop. The path becomes healthy at its first ACK.

The client removes a path in this order:

1. It stops the REGISTER loop.
2. It clears the bit of the path in `path_state`.
3. It clears the slot in the path mask of the group.
4. It clears the entry of the path in `path_config`.

The client program thus never picks a path with a partial configuration. A result from an old REGISTER loop has no effect on a new path in the same slot. The client does not remove the last path of a group. The server needs no change, because it learns each path from its REGISTER frames. The lease of a removed path ends after 30 seconds.

A group with egress paths also takes runtime changes of its egress paths. A new egress path takes the lowest free egress path slot, and it is unhealthy until its first probe. The client writes it to `client_down_paths`, adds it to the egress mask of the group, and sends it with the next EGRESS_REGISTER frames. A removed egress path leaves the egress mask first. Then the client sends it with a lease of zero for one lease, so the servers stop to use it within 10 seconds. A new egress mode reaches the servers with the next REGISTER. The client does not remove the last egress path of a group. It does not add an egress path to a group without egress paths.

Path changes are not saved. At the next start, the daemon uses its flags or its configuration file again.

## Trust model

MUP has no keys and no authentication of its own. It relies on these facts:

- WireGuard authenticates its handshake and its encrypted payload end to end.
- The server accepts data only on a live registered path, and the path gives the client key.
- The client accepts egress packets only from the paths of the group of the peer: from the server of a path, from the return IP of a path, or from an egress path of the group.
- The target accepts only valid WireGuard messages.

A host can spoof the source address of a registered client. That host can then register paths for the client, change its return mode, and drop or misroute its traffic. It cannot read or forge WireGuard payloads. Use MUP only on networks where you control the hosts and the routing.

The duplicate cache is a filter for repeater copies, not a replay defense. WireGuard provides replay protection for its transport data.

A bridge keeps the source of each ingress packet, and it sends only MUP packets and only to the server of its entry. So the ingress through a bridge gives no host a new way to spoof an address. On the egress, a bridge sends packets with any source. So it takes wrapped replies only from the entry server and the entry `allow` ranges, and only with a MUP packet inside. With a bridge via, an `allow` range holds the members of the via. A host that spoofs the address of the server can still make the bridge send MUP packets to any address.

## Limits

- MUP supports IPv4 only. It forwards no IPv4 options and no fragments.
- The largest WireGuard message is the path MTU minus 28 bytes, which is 1472 bytes at MTU 1500. WireGuard needs no MTU change.
- A client has up to 8 paths and 8 egress paths in all groups. The bridges of a direction count as its paths.
- The bridge wrapper adds 20 bytes. On an egress bridge, the largest WireGuard message is the path MTU minus 48 bytes.
- An egress path has one server port, and it does not move to another port.
- A client serves up to 4095 peers in all groups. A server holds up to 41000 routes and 4096 registrations.
- One peer source IP has up to 1024 routes on a client. The count can be too low for one second after a new route.
- Each active client of a server needs its own advertised IP.
- A server port range has up to 4096 ports. The server opens one UDP control socket for each port.
- A client binds one UDP control socket to `-s` and the listen port of each group with a UDP path. If another program holds that port, the client does not start.
- On an ICMP path with a return IP, the server reaches the reflector only through the interface that faces the client.
- On a path without a source range, the control frames travel in the data flow. So a filter that blocks a flow because of its control frames also blocks the data of that path.
- A path with a source range needs a server of v0.5.1 or later, except a UDP ingress path. A client behind NAT cannot use a source range.
- A client has up to 8 path tags, one for each path slot, and the tag takes 4 bits of the ICMP Echo sequence. The peer token keeps the other 12 bits.
- MUP attaches only to the interfaces that are ingress at start.
- MUP supports only interfaces with an Ethernet header, and the loopback interface. Peers that arrive on another interface get no service.
- The server treats every UDP packet from the target address and port to its source IP as a reply. Do not run other clients of the same target on the server host with that source IP.
- MUP needs a complete transport checksum on each input packet. There are two exceptions: a reply of a target on the server host, and a packet from WireGuard on the client host. MUP handles these as partial checksums. Other local traffic through a veth pair with checksum offload can carry an unfinished checksum, and MUP does not support it.
