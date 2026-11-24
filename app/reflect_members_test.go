package app

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/xshecan/mup/config"
	"github.com/xshecan/mup/dataplane"
)

func memberAddrs(raw ...string) []netip.Addr {
	var addresses []netip.Addr
	for _, text := range raw {
		addresses = append(addresses, netip.MustParseAddr(text))
	}
	return addresses
}

func TestAMemberStaysPublishedForTwoMissedRoundsAndLeavesOnTheThird(t *testing.T) {
	t.Parallel()

	candidates := memberAddrs("203.0.113.1", "203.0.113.2")
	set := newReflectMemberSet(candidates)
	if published, pending := set.round(candidates); !slices.Equal(published, candidates) || pending {
		t.Fatalf("first round = %v pending %v, want both members and no pending member", published, pending)
	}
	only := candidates[:1]
	for round := 1; round < missLimit; round++ {
		published, pending := set.round(only)
		if !slices.Equal(published, candidates) || !pending {
			t.Fatalf("missed round %d = %v pending %v, want both members and a pending member", round, published, pending)
		}
	}
	published, pending := set.round(only)
	if !slices.Equal(published, only) || pending {
		t.Fatalf("third missed round = %v pending %v, want only the first member and no pending member", published, pending)
	}
	published, pending = set.round(candidates)
	if !slices.Equal(published, candidates) || pending {
		t.Fatalf("answer after the removal = %v pending %v, want both members back at once", published, pending)
	}
}

func TestAMemberThatNeverAnsweredIsNotPublished(t *testing.T) {
	t.Parallel()

	candidates := memberAddrs("203.0.113.1", "203.0.113.2", "203.0.113.3")
	set := newReflectMemberSet(candidates)
	for round := 0; round < missLimit+1; round++ {
		published, pending := set.round(memberAddrs("203.0.113.2"))
		if !slices.Equal(published, candidates[1:2]) || pending {
			t.Fatalf("round %d = %v pending %v, want only the member that answered", round, published, pending)
		}
	}
	if published, pending := set.round(nil); len(published) != 1 || !pending {
		t.Fatalf("round without an answer = %v pending %v, want the member that answered before, pending", published, pending)
	}
}

func TestThePublishedMembersFollowTheOrderOfTheCandidates(t *testing.T) {
	t.Parallel()

	candidates := memberAddrs("203.0.113.1", "203.0.113.2", "203.0.113.3")
	set := newReflectMemberSet(candidates)
	if published, _ := set.round(memberAddrs("203.0.113.3", "203.0.113.1", "203.0.113.2")); !slices.Equal(published, candidates) {
		t.Fatalf("published = %v, want the candidate order", published)
	}
	if published, _ := set.round(memberAddrs("203.0.113.2", "203.0.113.3", "203.0.113.1")); !slices.Equal(published, candidates) {
		t.Fatalf("published = %v, want the candidate order", published)
	}
}

func TestASingleViaHostStaysPublishedLikeAPoolMember(t *testing.T) {
	t.Parallel()

	host := memberAddrs("203.0.113.9")
	set := newReflectMemberSet(host)
	if published, pending := set.round(nil); len(published) != 0 || pending {
		t.Fatalf("round before any answer = %v pending %v, want nothing", published, pending)
	}
	set.round(host)
	for round := 1; round < missLimit; round++ {
		if published, pending := set.round(nil); !slices.Equal(published, host) || !pending {
			t.Fatalf("missed round %d = %v pending %v, want the host, pending", round, published, pending)
		}
	}
	if published, pending := set.round(nil); len(published) != 0 || pending {
		t.Fatalf("third missed round = %v pending %v, want an empty list", published, pending)
	}
}

func TestAReflectPathChecksAgainSoonWhileAMemberIsPending(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		acked, pending bool
		want           time.Duration
	}{
		"acked and settled":  {acked: true, want: registrationRefresh},
		"acked and pending":  {acked: true, pending: true, want: registrationRetry},
		"missed":             {want: registrationRetry},
		"missed and pending": {pending: true, want: registrationRetry},
	} {
		if got := reflectRegistrationDelay(test.acked, test.pending); got != test.want {
			t.Fatalf("%s: delay = %s, want %s", name, got, test.want)
		}
	}
}

// newReflectController starts a client with one ingress reflect path in slot 0.
func newReflectController(t *testing.T) (controllerFixture, map[int]pathRegistration) {
	t.Helper()
	group := testGroup(t, 51820, config.ModeFailover, "198.51.100.1:9000/udp via 203.0.113.0/30")
	group.EgressPaths = append(group.EgressPaths, mustParsePath(t, "198.51.100.1:9300/udp"))
	client := config.Client{AdvertisedIP: netip.MustParseAddr("192.0.2.10"), Groups: []config.Group{group}}
	if err := client.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	plan, err := buildPlan(config.App{Client: &client}, 42, fakeResolver{catchAll: 2})
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	fake := &fakeClientDataplane{paths: map[int]dataplane.PathSettings{}, groups: map[uint16]dataplane.GroupSettings{}}
	controls := &fakeControls{registrations: map[int]pathRegistration{}}
	controller := newClientController(client, *plan.client, fake, fakeResolver{catchAll: 2}, controls, time.Unix(100, 0), discardLogger)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := controller.start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	return controllerFixture{controller: controller, dataplane: fake}, controls.registrations
}

func TestAnEmptyMemberListDoesNotReachTheDataplane(t *testing.T) {
	t.Parallel()

	fixture, registrations := newReflectController(t)
	registration := registrations[0]
	members := memberAddrs("203.0.113.1", "203.0.113.2")
	if err := registration.writeMembers(members); err != nil {
		t.Fatalf("writeMembers: %v", err)
	}
	if err := registration.writeMembers(nil); err != nil {
		t.Fatalf("writeMembers with an empty list: %v", err)
	}
	if got := fixture.dataplane.reflect[0]; !slices.Equal(got, members) {
		t.Fatalf("dataplane list = %v, want the last non-empty list %v", got, members)
	}
	for _, entry := range fixture.dataplane.log {
		if entry == "reflect 0 0" {
			t.Fatalf("dataplane log = %v, want no write of an empty list", fixture.dataplane.log)
		}
	}
	fixture.controller.reflectMu.Lock()
	healthy := fixture.controller.reflectHealthy[0]
	fixture.controller.reflectMu.Unlock()
	if len(healthy) != 0 {
		t.Fatalf("list of the probe replies = %v, want it empty", healthy)
	}
}

func TestAReflectPathEntersThePathMaskOnlyAfterItsFirstMemberList(t *testing.T) {
	t.Parallel()

	fixture, registrations := newReflectController(t)
	if fixture.dataplane.mask&1 != 0 {
		t.Fatalf("mask = %#b at start, want the reflect path out of it until it has members", fixture.dataplane.mask)
	}
	if err := registrations[0].writeMembers(memberAddrs("203.0.113.1")); err != nil {
		t.Fatalf("writeMembers: %v", err)
	}
	fixture.reply(t, 0, 1)
	if fixture.dataplane.mask&1 == 0 || len(fixture.dataplane.reflect[0]) != 1 {
		t.Fatalf("mask = %#b, list = %v after the first answer, want the path in the mask with its member", fixture.dataplane.mask, fixture.dataplane.reflect[0])
	}
}

func TestAReflectPathAddedAtRunTimeEntersThePathMaskOnlyAfterItsFirstMemberList(t *testing.T) {
	t.Parallel()

	fixture, _ := newReflectController(t)
	controls := fixture.controller.controls.(*fakeControls)
	added, err := fixture.controller.AddPath("198.51.100.1:9001/udp via 203.0.113.8", 51820)
	if err != nil {
		t.Fatalf("AddPath: %v", err)
	}
	slot := added.ID
	if fixture.dataplane.mask&(1<<slot) != 0 {
		t.Fatalf("mask = %#b after the add, want the new reflect path out of it", fixture.dataplane.mask)
	}
	if err := controls.registrations[slot].writeMembers(memberAddrs("203.0.113.8")); err != nil {
		t.Fatalf("writeMembers: %v", err)
	}
	fixture.reply(t, slot, 1)
	if fixture.dataplane.mask&(1<<slot) == 0 || len(fixture.dataplane.reflect[slot]) != 1 {
		t.Fatalf("mask = %#b, list = %v after the first answer, want the path in the mask with its member", fixture.dataplane.mask, fixture.dataplane.reflect[slot])
	}
}
