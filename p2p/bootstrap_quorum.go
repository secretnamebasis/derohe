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

// kata cycle 13: trust-minimized peer selection for fast-sync's bootstrap
// manifest (Peer.ChangeSet). TreeSection is unable to prove a chunk was
// answered honestly (unlike blocks, which self-verify via hash/PoW/parent
// chain) - bootstrap_chain() previously trusted whichever single peer
// answered outright. This replaces that with a three-tier confidence model:
//
//   Tier 1 (swarm quorum):       >15 eligible peers  -> need >=15 matching
//   Tier 2 (proportional quorum): 3-15 eligible peers -> need >=ceil(33%)
//   Tier 3 (trusted floor):      <3 eligible peers, or no tier reaches its
//                                 threshold -> a single operator-configured
//                                 --add-priority-node peer if one is
//                                 connected and eligible, else the original
//                                 peer trigger_sync already chose (today's
//                                 unchanged behavior, the ultimate fallback).
//
// Scope for this cycle: applied to the manifest call only. The three
// TreeSection chunk-fetch phases (balance tree, SC-meta tree, per-SC data
// trees) still fetch from a single peer post-manifest, same as before -
// per-chunk quorum is real, well-scoped follow-up work, not attempted here.

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deroproject/derohe/globals"
)

const bootstrap_swarm_threshold = 15  // >15 eligible -> tier 1
const bootstrap_quorum_min_sample = 3 // <3 eligible -> tier 3, a percentage of a tiny sample proves nothing

type bootstrap_tier int

const (
	bootstrap_tier_swarm bootstrap_tier = iota
	bootstrap_tier_proportional
	bootstrap_tier_trusted
)

// select_bootstrap_tier maps an eligible-peer count to its confidence tier
// and the number of matching responses required at that tier.
func select_bootstrap_tier(eligible_count int) (tier bootstrap_tier, threshold int) {
	switch {
	case eligible_count > bootstrap_swarm_threshold:
		return bootstrap_tier_swarm, bootstrap_swarm_threshold
	case eligible_count >= bootstrap_quorum_min_sample:
		threshold = int(ceil_div(int64(eligible_count)*33, 100))
		return bootstrap_tier_proportional, threshold
	default:
		return bootstrap_tier_trusted, 1
	}
}

// ceil_div returns ceil(a/b) for positive a, b - avoids pulling in math.Ceil
// for a single integer-friendly computation.
func ceil_div(a, b int64) int64 {
	if b == 0 {
		return 0
	}
	return (a + b - 1) / b
}

// bootstrap_eligible_peers filters candidates to those with state available
// at the target topoheight - confirmed via blockchain/prune_history.go's
// rewrite_graviton_store that Pruned tracks state-tree retention, not just
// block-history retention, so the same relationship block-sync uses applies
// here too, just as a single per-peer check against one fixed target height
// instead of a per-unit check across a range.
func bootstrap_eligible_peers(candidates []*Connection, target int64) (eligible []*Connection) {
	for _, c := range candidates {
		if atomic.LoadUint32(&c.State) == HANDSHAKE_PENDING {
			continue
		}
		if atomic.LoadInt64(&c.TopoHeight) >= target && atomic.LoadInt64(&c.Pruned) <= target {
			eligible = append(eligible, c)
		}
	}
	return
}

// is_trusted_peer checks whether a connection's address matches one of the
// operator's explicitly configured --add-priority-node entries. Connection
// has no per-peer trust field (SyncNode is a global mode flag, not a
// per-address marker - confirmed by controller.go:688's SyncNode: sync_node
// using the package-level bool for every connection uniformly), so this
// checks the real configured address list directly instead.
func is_trusted_peer(connection *Connection) bool {
	v, ok := globals.Arguments["--add-priority-node"]
	if !ok || v == nil {
		return false
	}
	list, ok := v.([]string)
	if !ok {
		return false
	}
	addr := connection.Addr.String()
	for _, p := range list {
		if p == addr {
			return true
		}
	}
	return false
}

// quorum_fetch queries `peers` concurrently via fetch_fn, groups responses
// by their reported content hash, and returns the largest matching group's
// representative response once that group's size reaches `threshold`.
// fetch_fn should hash only the semantically meaningful response content
// (excluding per-connection fields like Common, which legitimately differ
// between honest peers even when the underlying data agrees).
func quorum_fetch(peers []*Connection, threshold int, fetch_fn func(*Connection) (hash [32]byte, response interface{}, ok bool)) (winner interface{}, agreeing []*Connection, ok bool) {
	type result struct {
		conn *Connection
		hash [32]byte
		resp interface{}
		ok   bool
	}
	results := make(chan result, len(peers))
	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(p *Connection) {
			defer wg.Done()
			h, r, ok := fetch_fn(p)
			results <- result{conn: p, hash: h, resp: r, ok: ok}
		}(p)
	}
	wg.Wait()
	close(results)

	groups := map[[32]byte][]result{}
	for r := range results {
		if !r.ok {
			continue
		}
		groups[r.hash] = append(groups[r.hash], r)
	}

	var best_hash [32]byte
	best_count := 0
	for h, g := range groups {
		if len(g) > best_count {
			best_count = len(g)
			best_hash = h
		}
	}
	if best_count < threshold {
		return nil, nil, false
	}
	g := groups[best_hash]
	for _, r := range g {
		agreeing = append(agreeing, r.conn)
	}
	return g[0].resp, agreeing, true
}

// hash_changes_response computes a canonical hash of a Changes response's
// meaningful content (CBlocks, KeyCount, SCKeyCount) - deliberately
// excluding Common, which carries per-connection fields (e.g. timing) that
// legitimately differ between honest peers reporting the same chain state.
func hash_changes_response(c *Changes) [32]byte {
	h := sha256.New()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(c.KeyCount))
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(c.SCKeyCount))
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(len(c.CBlocks)))
	h.Write(buf[:])
	for _, cb := range c.CBlocks {
		binary.BigEndian.PutUint64(buf[:], uint64(len(cb.Block)))
		h.Write(buf[:])
		h.Write(cb.Block)
		h.Write([]byte(cb.Difficulty))
		binary.BigEndian.PutUint64(buf[:], uint64(len(cb.Txs)))
		h.Write(buf[:])
		for _, tx := range cb.Txs {
			binary.BigEndian.PutUint64(buf[:], uint64(len(tx)))
			h.Write(buf[:])
			h.Write(tx)
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// fetch_bootstrap_manifest fetches the Peer.ChangeSet manifest with tiered
// trust-minimization instead of blindly trusting fallback_connection alone.
// Returns the agreed manifest and which connection to use for the rest of
// bootstrap_chain()'s (unchanged) single-peer chunk-fetching - any one of
// the quorum-agreeing peers, the trusted peer, or fallback_connection
// itself when nothing better is available, preserving today's exact
// behavior as the true last resort.
const bootstrap_warmup_target_peers = 16 // just past the Tier 1 threshold, giving it a fair shot
const bootstrap_warmup_timeout = 120 * time.Second
const bootstrap_warmup_poll_interval = 2 * time.Second

// bootstrap_warmup_done tracks whether the warm-up has already run once.
// Deliberately NOT piggybacked on state.Height/state.Step - bootstrap_chain()
// already sets state.Height = connection.TopoHeight BEFORE calling
// fetch_bootstrap_manifest() on the very first attempt, so checking
// state.Height here would always see it non-zero and skip the wait even on
// the genuine first call (a real bug caught live: zero warmup_wait log
// lines ever appeared, even on a fresh run - confirmed by checking the
// actual log instead of assuming the fix worked).
var bootstrap_warmup_done bool

// bootstrap_warmup_wait lets the real peer pool grow before the manifest
// tier decision fires. Real observation (this session, live): trigger_sync
// fires the first bootstrap attempt only ~5-6 seconds after P2P startup,
// on whatever tiny connection count exists at that instant - not because
// enough real peers don't exist, but because nothing ever waited for them.
// Only waits once per process lifetime - retries on later ticks proceed
// immediately, since re-waiting on every ~4s retry would compound delay
// for no benefit.
func bootstrap_warmup_wait(target int64) {
	if bootstrap_warmup_done {
		return
	}
	bootstrap_warmup_done = true
	start := time.Now()
	for time.Since(start) < bootstrap_warmup_timeout {
		all := []*Connection{}
		for _, c := range UniqueConnections() {
			all = append(all, c)
		}
		eligible := bootstrap_eligible_peers(all, target)
		if len(eligible) >= bootstrap_warmup_target_peers {
			logger.V(1).Info("bootstrap_warmup_wait: target reached", "eligible_peers", len(eligible), "elapsed", time.Since(start))
			return
		}
		time.Sleep(bootstrap_warmup_poll_interval)
	}
	logger.V(1).Info("bootstrap_warmup_wait: timed out, proceeding with whatever peer pool exists", "elapsed", time.Since(start))
}

func fetch_bootstrap_manifest(fallback_connection *Connection, request ChangeList) (manifest *Changes, chosen *Connection, err error) {
	target := fallback_connection.TopoHeight
	bootstrap_warmup_wait(target)
	all := []*Connection{}
	for _, c := range UniqueConnections() {
		all = append(all, c)
	}
	eligible := bootstrap_eligible_peers(all, target)

	tier, threshold := select_bootstrap_tier(len(eligible))
	logger.V(1).Info("fetch_bootstrap_manifest: tier selected", "target", target, "eligible_peers", len(eligible), "tier", tier, "threshold", threshold)

	fetch_one := func(c *Connection) (h [32]byte, resp interface{}, ok bool) {
		r := request
		fill_common(&r.Common)
		var response Changes
		if err := c.Client.Call("Peer.ChangeSet", r, &response); err != nil {
			return h, nil, false
		}
		return hash_changes_response(&response), &response, true
	}

	if tier == bootstrap_tier_swarm || tier == bootstrap_tier_proportional {
		if winner, agreeing, ok := quorum_fetch(eligible, threshold, fetch_one); ok {
			logger.V(1).Info("fetch_bootstrap_manifest: quorum reached", "tier", tier, "agreeing_peers", len(agreeing), "threshold", threshold)
			return winner.(*Changes), agreeing[0], nil
		}
		logger.V(1).Info("fetch_bootstrap_manifest: quorum NOT reached at this tier, falling through", "tier", tier, "threshold", threshold)
	}

	// tier 3: a trusted peer if one is connected and eligible
	for _, c := range eligible {
		if is_trusted_peer(c) {
			logger.V(1).Info("fetch_bootstrap_manifest: using trusted peer", "addr", c.Addr.String())
			var response Changes
			r := request
			fill_common(&r.Common)
			if err := c.Client.Call("Peer.ChangeSet", r, &response); err == nil {
				return &response, c, nil
			}
		}
	}

	// ultimate fallback: today's original, unchanged behavior
	logger.V(1).Info("fetch_bootstrap_manifest: no trusted peer available, falling back to original single-peer behavior", "addr", fallback_connection.Addr.String())
	var response Changes
	r := request
	fill_common(&r.Common)
	if err := fallback_connection.Client.Call("Peer.ChangeSet", r, &response); err != nil {
		return nil, nil, err
	}
	return &response, fallback_connection, nil
}
