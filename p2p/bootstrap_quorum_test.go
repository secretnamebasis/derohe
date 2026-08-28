// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package p2p

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"testing"

	"github.com/deroproject/derohe/globals"
)

func make_test_pool_conn(port int, latency int64) *Connection {
	return &Connection{
		Addr:    &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port},
		Latency: latency,
	}
}

// Test_Live_Peer_Pool_Pick_Prefers_Low_Latency_Top_K asserts pick()'s actual
// selection distribution, not just that it runs without panicking - cycle
// 24's own obstacle list called out that a weaker test would repeat cycle
// 21's mistake (visibility/behavior code that doesn't verify what it
// claims). With 8 peers at distinct latencies and top_k=4, every pick()
// call across a large index range must land on one of the 4 genuinely
// lowest-latency peers, and all 4 of them must actually be reachable -
// ruling out both "picks outside the intended window" and "collapses onto
// fewer than top_k peers despite top_k being available".
func Test_Live_Peer_Pool_Pick_Prefers_Low_Latency_Top_K(t *testing.T) {
	type peer_spec struct {
		port    int
		latency int64
	}
	specs := []peer_spec{
		{20301, 300}, {20302, 50}, {20303, 400}, {20304, 10},
		{20305, 200}, {20306, 20}, {20307, 500}, {20308, 100},
	}
	var peers []*Connection
	for _, s := range specs {
		peers = append(peers, make_test_pool_conn(s.port, s.latency))
	}

	want_top_k := append([]*Connection{}, peers...)
	sort.SliceStable(want_top_k, func(i, j int) bool {
		return bootstrap_effective_latency(want_top_k[i]) < bootstrap_effective_latency(want_top_k[j])
	})
	want_top_k = want_top_k[:bootstrap_pick_top_k]
	want_addrs := map[string]bool{}
	for _, c := range want_top_k {
		want_addrs[c.Addr.String()] = true
	}

	pool := new_bootstrap_live_peer_pool(peers)
	seen := map[string]bool{}
	for i := int64(0); i < 40; i++ {
		picked := pool.pick(i)
		if picked == nil {
			t.Fatalf("pick(%d) returned nil with %d live peers", i, len(peers))
		}
		addr := picked.Addr.String()
		if !want_addrs[addr] {
			t.Fatalf("pick(%d) returned %s, latency %d - not among the %d lowest-latency peers %v",
				i, addr, picked.Latency, bootstrap_pick_top_k, want_addrs)
		}
		seen[addr] = true
	}
	if len(seen) != bootstrap_pick_top_k {
		t.Fatalf("expected all %d top-k peers to be reachable via pick(), only saw %d: %v", bootstrap_pick_top_k, len(seen), seen)
	}
}

// Test_Live_Peer_Pool_Pick_Treats_Unmeasured_Latency_As_Worst guards the
// specific failure mode cycle 24's own obstacle list called out: a naive
// ascending sort would leave an unmeasured peer (Latency == 0, its Go zero
// value) at the front, wrongly treating "we haven't measured this peer
// yet" as "this is the fastest peer". With one unmeasured peer among more
// than top_k real-latency peers, the unmeasured one must never appear in
// pick()'s rotation.
func Test_Live_Peer_Pool_Pick_Treats_Unmeasured_Latency_As_Worst(t *testing.T) {
	unmeasured := make_test_pool_conn(20401, 0)
	peers := []*Connection{
		unmeasured,
		make_test_pool_conn(20402, 10),
		make_test_pool_conn(20403, 20),
		make_test_pool_conn(20404, 30),
		make_test_pool_conn(20405, 40),
		make_test_pool_conn(20406, 50),
	}
	pool := new_bootstrap_live_peer_pool(peers)
	unmeasured_addr := unmeasured.Addr.String()
	for i := int64(0); i < 40; i++ {
		picked := pool.pick(i)
		if picked.Addr.String() == unmeasured_addr {
			t.Fatalf("pick(%d) returned the unmeasured (Latency=0) peer - it should sort last, not first", i)
		}
	}
}

// Test_Live_Peer_Pool_Mark_Dead_Repromotes_Next_Fastest confirms the
// bounded top-k window actually refills from the next-fastest survivor
// once a top-k peer dies, rather than pick() silently rotating a smaller
// effective window forever.
func Test_Live_Peer_Pool_Mark_Dead_Repromotes_Next_Fastest(t *testing.T) {
	fastest := make_test_pool_conn(20501, 10)
	second := make_test_pool_conn(20502, 20)
	third := make_test_pool_conn(20503, 30)
	fourth := make_test_pool_conn(20504, 40)
	fifth_excluded := make_test_pool_conn(20505, 50) // outside top_k=4 initially

	pool := new_bootstrap_live_peer_pool([]*Connection{fastest, second, third, fourth, fifth_excluded})

	excluded_addr := fifth_excluded.Addr.String()
	for i := int64(0); i < 20; i++ {
		if pool.pick(i).Addr.String() == excluded_addr {
			t.Fatalf("pick(%d) returned the 5th-fastest peer while top_k=4 peers were still live", i)
		}
	}

	if !pool.mark_dead(fastest.Addr.String()) {
		t.Fatalf("mark_dead should report true removing a live peer")
	}

	promoted := false
	for i := int64(0); i < 20; i++ {
		if pool.pick(i).Addr.String() == excluded_addr {
			promoted = true
			break
		}
	}
	if !promoted {
		t.Fatalf("expected the 5th-fastest peer to be promoted into the top-k window after the fastest peer died")
	}
}

// Test_Live_Peer_Pool_Concurrent_Pick_And_Mark_Dead is the load-bearing
// -race check for this cycle's change: pick() and mark_dead() are called
// concurrently from many goroutines in real bootstrap runs (cycles 20/22
// already established this), and the new sort-on-mutation logic must not
// introduce a race or a panic under that same concurrency.
func Test_Live_Peer_Pool_Concurrent_Pick_And_Mark_Dead(t *testing.T) {
	var peers []*Connection
	for i := 0; i < 30; i++ {
		peers = append(peers, make_test_pool_conn(20600+i, int64(i+1)*7))
	}
	pool := new_bootstrap_live_peer_pool(peers)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := int64(0); i < 200; i++ {
				pool.pick(int64(g)*200 + i)
			}
		}(g)
	}
	for _, c := range peers[:10] {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			pool.mark_dead(addr)
		}(c.Addr.String())
	}
	wg.Wait()
}

func Test_Select_Bootstrap_Tier_Boundaries(t *testing.T) {
	cases := []struct {
		count          int
		want_tier      bootstrap_tier
		want_threshold int
	}{
		{2, bootstrap_tier_trusted, 1},       // below min sample -> trusted floor
		{3, bootstrap_tier_proportional, 1},  // ceil(3*0.33)=1
		{10, bootstrap_tier_proportional, 4}, // ceil(10*0.33)=ceil(3.3)=4
		{15, bootstrap_tier_proportional, 5}, // ceil(15*0.33)=ceil(4.95)=5, still <=15 so not swarm
		{16, bootstrap_tier_swarm, 15},       // >15 -> swarm, flat threshold of 15
		{100, bootstrap_tier_swarm, 15},      // still flat 15 regardless of how far over
	}
	for _, c := range cases {
		tier, threshold := select_bootstrap_tier(c.count)
		if tier != c.want_tier || threshold != c.want_threshold {
			t.Errorf("count=%d: got tier=%v threshold=%d, want tier=%v threshold=%d", c.count, tier, threshold, c.want_tier, c.want_threshold)
		}
	}
}

func Test_Quorum_Fetch_Accepts_Majority_Rejects_Below_Threshold(t *testing.T) {
	mk := func(port int) *Connection {
		addr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", 20200+port))
		return &Connection{Addr: addr}
	}
	peers := []*Connection{mk(1), mk(2), mk(3), mk(4), mk(5)}

	// 4 of 5 agree on hash A, 1 reports hash B - threshold 4 should accept the majority.
	hash_a := [32]byte{0xAA}
	hash_b := [32]byte{0xBB}
	fetch_fn := func(c *Connection) (h [32]byte, resp interface{}, ok bool) {
		if c == peers[4] {
			return hash_b, "minority", true
		}
		return hash_a, "majority", true
	}

	winner, agreeing, ok := quorum_fetch(peers, 4, fetch_fn)
	if !ok {
		t.Fatalf("expected quorum reached (4 of 5 agree), got not ok")
	}
	if winner.(string) != "majority" {
		t.Fatalf("expected winner 'majority', got %v", winner)
	}
	if len(agreeing) != 4 {
		t.Fatalf("expected 4 agreeing peers, got %d", len(agreeing))
	}

	// Same data, but threshold 5 (unanimous) should now fail - only 4 agree.
	_, _, ok = quorum_fetch(peers, 5, fetch_fn)
	if ok {
		t.Fatalf("expected quorum NOT reached at threshold 5 (only 4 agree), got ok")
	}
}

func Test_Is_Trusted_Peer_Checks_Real_Priority_Node_List(t *testing.T) {
	saved := globals.Arguments["--add-priority-node"]
	defer func() { globals.Arguments["--add-priority-node"] = saved }()

	trusted_addr, _ := net.ResolveTCPAddr("tcp", "203.0.113.5:11011")
	untrusted_addr, _ := net.ResolveTCPAddr("tcp", "203.0.113.9:11011")

	globals.Arguments = map[string]interface{}{
		"--add-priority-node": []string{"203.0.113.5:11011"},
	}

	trusted_conn := &Connection{Addr: trusted_addr}
	untrusted_conn := &Connection{Addr: untrusted_addr}

	if !is_trusted_peer(trusted_conn) {
		t.Fatalf("expected %s to be trusted (matches configured priority node)", trusted_addr)
	}
	if is_trusted_peer(untrusted_conn) {
		t.Fatalf("expected %s to NOT be trusted (not in priority node list)", untrusted_addr)
	}

	// no priority nodes configured at all -> nothing is trusted
	globals.Arguments = map[string]interface{}{}
	if is_trusted_peer(trusted_conn) {
		t.Fatalf("expected no peer to be trusted when --add-priority-node is unset")
	}
}

// Test_Pick_Alternate_Diversifies_Within_Top_K asserts pick_alternate's
// actual selection distribution - cycle 25 found the old always-first-match
// behavior explained most of one live run's peer-credit skew (940 of 1452
// ticks, 65%, to one peer), so a test that only checks "returns SOME peer"
// would miss the exact defect that motivated this fix. With 6 peers (top_k=4)
// and none tried yet, repeated calls must land on more than one of the top-4
// fastest, and must never return a peer outside that window while any of the
// top-4 remain untried.
func Test_Pick_Alternate_Diversifies_Within_Top_K(t *testing.T) {
	peers := []*Connection{
		make_test_pool_conn(20701, 10), // top-4 by latency
		make_test_pool_conn(20702, 20),
		make_test_pool_conn(20703, 30),
		make_test_pool_conn(20704, 40),
		make_test_pool_conn(20705, 50), // outside top-4
		make_test_pool_conn(20706, 60), // outside top-4
	}
	pool := new_bootstrap_live_peer_pool(peers)
	top4 := map[string]bool{}
	for _, c := range peers[:4] {
		top4[c.Addr.String()] = true
	}

	seen := map[string]bool{}
	for i := 0; i < 60; i++ {
		alt := pool.pick_alternate(map[string]bool{})
		if alt == nil {
			t.Fatalf("pick_alternate(%d) returned nil with peers untried", i)
		}
		if !top4[alt.Addr.String()] {
			t.Fatalf("pick_alternate(%d) returned %s, outside the top-4 window, while top-4 candidates remain untried", i, alt.Addr.String())
		}
		seen[alt.Addr.String()] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected pick_alternate to diversify across the top-4 window over 60 calls, only ever returned: %v", seen)
	}
}

// Test_Pick_Alternate_Falls_Back_Once_Top_K_Exhausted confirms the outside-
// the-window peers are only reachable once every top-k candidate has
// already been tried for this chunk, not before.
func Test_Pick_Alternate_Falls_Back_Once_Top_K_Exhausted(t *testing.T) {
	peers := []*Connection{
		make_test_pool_conn(20711, 10),
		make_test_pool_conn(20712, 20),
		make_test_pool_conn(20713, 30),
		make_test_pool_conn(20714, 40),
		make_test_pool_conn(20715, 50), // outside top-4
	}
	pool := new_bootstrap_live_peer_pool(peers)

	already_tried := map[string]bool{}
	for _, c := range peers[:4] {
		already_tried[c.Addr.String()] = true
	}

	alt := pool.pick_alternate(already_tried)
	if alt == nil {
		t.Fatalf("expected a fallback candidate once the top-4 are exhausted")
	}
	if alt.Addr.String() != peers[4].Addr.String() {
		t.Fatalf("expected the sole remaining peer %s, got %s", peers[4].Addr.String(), alt.Addr.String())
	}

	already_tried[peers[4].Addr.String()] = true
	if exhausted := pool.pick_alternate(already_tried); exhausted != nil {
		t.Fatalf("expected nil once every live peer has been tried, got %+v", exhausted)
	}
}
