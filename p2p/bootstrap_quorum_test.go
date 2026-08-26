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
	"testing"

	"github.com/deroproject/derohe/globals"
)

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
