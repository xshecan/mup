package dataplane

// rebuiltPins are the maps whose content the daemon can lose: counters, and
// state that the daemon or its clients write again soon after a start. The
// loader removes the pin of such a map when its layout changed, so a new
// version starts over the pins of an old one. The client writes every slot of
// path_config at each start. v0.4.0 grew the drop counters and the egress path
// entries, and v0.4.1 grew the path slots. v0.4.6 gave the registered paths and
// the server routes a listen port. The clients register again within a
// refresh, and the routes come back with the next packet, while the port pool
// reconciles the target ports of the lost routes.
//
// A pinned map that is not in this list must keep its layout, or the daemon
// does not start over its old pin. TestChangedPinsAreRebuilt checks this
// against the released versions in testdata/released_maps.json.
var rebuiltPins = []string{
	"stats", "event_limits", "path_config", "server_down_groups", "server_down_paths",
	"bridge_config", "bridge_addresses", "bridge_allow", "bridge_counters",
	"registered_paths", "server_route_by_key", "server_route_by_port",
}
