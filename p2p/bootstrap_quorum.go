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

// Trust-minimized peer selection for fast-sync's bootstrap manifest
// (Peer.ChangeSet). TreeSection is unable to prove a chunk was answered
// honestly (unlike blocks, which self-verify via hash/PoW/parent chain) -
// bootstrap_chain() previously trusted whichever single peer answered
// outright. This replaces that with a three-tier confidence model:
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
// The three TreeSection chunk-fetch phases (balance tree, SC-meta tree,
// per-SC data trees) now fan out across the same eligible-peer pool too
// (bootstrap_chunk_fanout_peers, wired into chain_bootstrap.go), instead of
// fetching everything from the single manifest-quorum-chosen peer. Full
// quorum on every chunk isn't attempted - it would multiply total network
// requests by the quorum size across potentially thousands of chunks, far
// more than the one-time manifest quorum costs. Instead, a random 1-in-N
// sample of chunks is spot-checked against a second peer
// (bootstrap_spot_check_chunk) - cheap, bounded overhead that can still
// catch a peer serving bad data for a subset of chunks, without paying
// full quorum cost on the whole state tree.

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
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

// bootstrap_chunk_fanout_peers returns the peer pool to fan TreeSection
// chunk-fetch requests across for the given target topoheight, reusing the
// same eligibility check already proven for the manifest quorum. Falls back
// to just the single connection bootstrap_chain() is already using when
// fewer than 2 peers are eligible, matching fanout_sync's own precedent
// (sync_fanout.go) of requiring at least 2 before attempting fan-out at
// all - so behavior is unchanged in the small-peer-pool case.
func bootstrap_chunk_fanout_peers(fallback *Connection, target int64) []*Connection {
	all := []*Connection{}
	for _, c := range UniqueConnections() {
		all = append(all, c)
	}
	eligible := bootstrap_eligible_peers(all, target)
	if len(eligible) < 2 {
		return []*Connection{fallback}
	}
	return eligible
}

// pick_alternate_chunk_peer returns the first eligible peer not yet tried
// for a specific chunk, for retrying a chunk-fetch failure against a
// different peer instead of aborting the whole attempt. Unlike
// pick_alternate_connection (sync_dispatch.go), this doesn't re-check
// Pruned/topoheight eligibility - peers passed in are already filtered by
// bootstrap_eligible_peers, and that filter doesn't change meaning between
// one chunk and the next the way per-block Pruned eligibility does across a
// range of topoheights. Returns nil once every eligible peer has been tried
// for this chunk - the caller then genuinely gives up, rather than retrying
// forever.
func pick_alternate_chunk_peer(peers []*Connection, already_tried map[string]bool) *Connection {
	for _, p := range peers {
		if !already_tried[p.Addr.String()] {
			return p
		}
	}
	return nil
}

// bootstrap_spot_check_sample_rate: 1-in-N chunks get re-checked against a
// second peer. Bounded overhead proportional to sample rate, not total
// chunk count - the whole point versus full per-chunk quorum.
const bootstrap_spot_check_sample_rate = 10

// hash_tree_section_response computes a canonical hash of a
// Response_Tree_Section_Struct's meaningful content (Keys, Values, in
// order) - same rationale as hash_changes_response: per-connection fields
// aren't part of this. Two honest peers walking the same deterministic
// tree section return keys in the same order (real tree traversal order,
// not peer-specific), so this doesn't need to sort before hashing.
func hash_tree_section_response(r *Response_Tree_Section_Struct) [32]byte {
	h := sha256.New()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(len(r.Keys)))
	h.Write(buf[:])
	for i := range r.Keys {
		binary.BigEndian.PutUint64(buf[:], uint64(len(r.Keys[i])))
		h.Write(buf[:])
		h.Write(r.Keys[i])
		binary.BigEndian.PutUint64(buf[:], uint64(len(r.Values[i])))
		h.Write(buf[:])
		h.Write(r.Values[i])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// bootstrap_spot_check_chunk re-requests the same TreeSection query from a
// different eligible peer than the one that originally answered, and logs
// (does not reject or retry) if the two responses disagree. Runs in its
// own goroutine, off the critical fetch/write path - a slow or failed
// spot-check must never block or fail the real bootstrap. Only a random
// 1-in-N sample is checked (bootstrap_spot_check_sample_rate), not every
// chunk - see this file's header comment for why full per-chunk quorum
// isn't attempted.
func bootstrap_spot_check_chunk(peers []*Connection, answered_by *Connection, original *Response_Tree_Section_Struct, tree_name string, topo int64, section []byte, section_length uint64, chunk_desc string) {
	if len(peers) < 2 {
		return // no second peer to check against
	}
	if rand.Intn(bootstrap_spot_check_sample_rate) != 0 {
		return // not sampled this time
	}

	var checker *Connection
	for _, p := range peers {
		if p != answered_by {
			checker = p
			break
		}
	}
	if checker == nil {
		return
	}

	go func() {
		ts_request := Request_Tree_Section_Struct{Topo: topo, TreeName: []byte(tree_name), Section: section, SectionLength: section_length}
		fill_common(&ts_request.Common)
		var ts_response Response_Tree_Section_Struct
		if err := checker.Client.Call("Peer.TreeSection", ts_request, &ts_response); err != nil {
			logger.V(2).Info("bootstrap spot-check: re-fetch failed, skipping", "chunk", chunk_desc, "checker", checker.Addr.String(), "err", err)
			return
		}
		if hash_tree_section_response(&ts_response) != hash_tree_section_response(original) {
			logger.Error(nil, "bootstrap spot-check: DISAGREEMENT between peers for the same chunk", "chunk", chunk_desc, "answered_by", answered_by.Addr.String(), "checked_by", checker.Addr.String())
			return
		}
		logger.V(3).Info("bootstrap spot-check: peers agree", "chunk", chunk_desc, "answered_by", answered_by.Addr.String(), "checked_by", checker.Addr.String())
	}()
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
		// this is the one manifest-fetch error that reaches bootstrap_fail
		// (quorum-tier and trusted-peer failures fall through to the next
		// option instead of returning an error) - drop the specific peer
		// that actually failed here, at the point where it's still known,
		// rather than leaving it to the caller's now-stale connection.
		fallback_connection.exit()
		return nil, nil, err
	}
	return &response, fallback_connection, nil
}
