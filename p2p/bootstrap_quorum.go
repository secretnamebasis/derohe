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
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
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

// bootstrap_live_peer_pool tracks the actual currently-live subset of a
// phase's fan-out peer pool (balance tree or SC-meta, including SC-meta's
// own nested per-SC fetches, which share the same instance as their
// enclosing outer loop), so peer selection stays genuinely even across
// whoever remains alive.
//
// The earlier design (bootstrap_known_dead_peers) skipped known-dead peers
// at lookup time but still probed forward through the ORIGINAL fixed
// snapshot's array order - that doesn't redistribute a dead peer's share
// evenly across survivors, it dumps it entirely onto whichever live peer
// happens to sit next in array order after a run of dead ones. Confirmed
// live: 61 percent of one phase's chunk traffic landing on a single peer,
// with 6 other survivors splitting the rest. This type instead REMOVES a
// peer from the live set once it's known dead, so picking evenly against
// whatever remains is the same plain, uniform operation round-robin always
// was - no probing, no positional bias, by construction.
type bootstrap_live_peer_pool struct {
	mu             sync.Mutex
	live           []*Connection  // kept sorted ascending by bootstrap_effective_latency
	timeout_counts map[string]int // addr -> bare-timeout count this phase, see handle_failure
}

// bootstrap_pick_top_k bounds how many of the fastest currently-live peers
// pick() rotates across. A deliberate, bounded concentration on proven-fast
// peers, instead of pick()'s previous plain modulo across the WHOLE live
// set - which, once that set shrank, collapsed traffic onto whoever
// happened to survive by accident (cycles 22/23 live data: a single
// survivor serving nearly all in-flight slots for extended stretches,
// independent of step 1's own request volume). Bounded rather than
// unbounded (e.g. always-the-single-fastest) so the fastest peer never
// becomes a lone point of failure while more than top_k peers remain live.
// Starting value, not yet tuned against live data - kata cycle 24 item 2.
const bootstrap_pick_top_k = 4

// bootstrap_pick_recipients returns how many distinct peers pick() can
// actually return out of a pool of the given size - min(bootstrap_pick_top_k,
// pool_size). A total in-flight request budget should be sized by this, not
// by the raw eligible-pool size: pick() only ever returns one of this many
// peers, so sizing the budget by a larger number means the excess gets
// funneled onto these same few recipients instead of the many peers it was
// meant to spread across.
func bootstrap_pick_recipients(pool_size int) int {
	if pool_size < bootstrap_pick_top_k {
		return pool_size
	}
	return bootstrap_pick_top_k
}

// bootstrap_effective_latency reads a peer's live, continuously-updated
// Latency (real RTT from timed syncs, see common.go's fill_common_T0T1T2
// path) as a sort key, treating an unmeasured peer (Latency <= 0 - a
// connection that hasn't completed a timed sync ping yet) as WORST-case,
// not best-case. A naive ascending sort with unmeasured peers left at their
// zero value would wrongly send them to the front, ahead of peers with
// real, but nonzero, measured latency.
func bootstrap_effective_latency(c *Connection) int64 {
	l := atomic.LoadInt64(&c.Latency)
	if l <= 0 {
		return math.MaxInt64
	}
	return l
}

// bootstrap_sort_by_latency sorts live ascending by bootstrap_effective_latency.
// Callers must hold p.mu.
func (p *bootstrap_live_peer_pool) sort_by_latency() {
	sort.SliceStable(p.live, func(i, j int) bool {
		return bootstrap_effective_latency(p.live[i]) < bootstrap_effective_latency(p.live[j])
	})
}

func new_bootstrap_live_peer_pool(peers []*Connection) *bootstrap_live_peer_pool {
	live := make([]*Connection, len(peers))
	copy(live, peers)
	p := &bootstrap_live_peer_pool{live: live}
	p.sort_by_latency()
	return p
}

// pick returns a peer for index i, chosen evenly from among only the
// bootstrap_pick_top_k fastest currently-live peers (all of them, if fewer
// than top_k remain - identical to the old plain-modulo behavior in that
// case). nil if every peer in the pool has been marked dead. live is kept
// sorted by latency (at construction and on every mark_dead removal, not
// on every pick - removals are comparatively rare against pick()'s
// per-request call frequency), so live[:k] is always the current top_k.
func (p *bootstrap_live_peer_pool) pick(i int64) *Connection {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.live) == 0 {
		return nil
	}
	k := bootstrap_pick_top_k
	if len(p.live) < k {
		k = len(p.live)
	}
	return p.live[i%int64(k)]
}

// mark_dead removes a peer from the live set - swap-with-last, then
// re-sorts by latency so live[:top_k] reflects the current fastest
// survivors (a dead top_k peer's slot is naturally backfilled by whoever's
// next-fastest, instead of pick() continuing to rotate a smaller effective
// window). Safe to call more than once for the same peer (a no-op after
// the first removal) - returns whether this call actually performed the
// removal, so a caller logging the event can tell a real first-time drop
// from a redundant later call against a peer that's already gone.
func (p *bootstrap_live_peer_pool) mark_dead(addr string) (removed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for idx, c := range p.live {
		if c.Addr.String() == addr {
			p.live[idx] = p.live[len(p.live)-1]
			p.live = p.live[:len(p.live)-1]
			p.sort_by_latency()
			return true
		}
	}
	return false
}

// pick_alternate returns a live peer not in already_tried, for retrying a
// chunk-fetch failure against a different peer instead of aborting the
// whole attempt. Unlike pick_alternate_connection (sync_dispatch.go), this
// doesn't re-check Pruned/topoheight eligibility - peers in the pool are
// already filtered by bootstrap_eligible_peers, and that filter doesn't
// change meaning between one chunk and the next the way per-block Pruned
// eligibility does across a range of topoheights. Returns nil once every
// live peer has been tried for this chunk - the caller then genuinely
// gives up, rather than retrying forever.
func (p *bootstrap_live_peer_pool) pick_alternate(already_tried map[string]bool) *Connection {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Returning the first untried peer in p.live's order (as this used to)
	// deterministically favors the SAME single peer for every retry across
	// a whole phase, since p.live is kept sorted ascending by latency -
	// stronger than an arbitrary fixed bias, this always means the single
	// fastest untried peer specifically. Live-caught (cycle 25): this
	// explained most of one phase's peer-credit skew (940 of 1452 ticks,
	// 65%, to one peer). Fixed to pick uniformly within the current top-k
	// window first (consistent with pick()'s own bounded-concentration
	// design over this same pool), falling back to the rest of the live
	// pool only once every top-k candidate has already been tried for this
	// chunk - a real, valid case, not treated as exhausted.
	k := bootstrap_pick_top_k
	if len(p.live) < k {
		k = len(p.live)
	}
	var window_candidates, rest_candidates []*Connection
	for i, c := range p.live {
		if already_tried[c.Addr.String()] {
			continue
		}
		if i < k {
			window_candidates = append(window_candidates, c)
		} else {
			rest_candidates = append(rest_candidates, c)
		}
	}
	if len(window_candidates) > 0 {
		return window_candidates[rand.Intn(len(window_candidates))]
	}
	if len(rest_candidates) > 0 {
		return rest_candidates[rand.Intn(len(rest_candidates))]
	}
	return nil
}

// bootstrap_peer_timeout_drop_threshold: a peer that never produces a real
// connection-level error but keeps hitting bootstrap_chunk_request_timeout
// anyway is still eventually treated as dead - a chronically overloaded or
// throttling peer shouldn't stay in the live pool forever just because it
// never technically errors. One bare timeout, on its own, is deliberately
// NOT enough (see handle_failure's own comment).
const bootstrap_peer_timeout_drop_threshold = 3

// errBootstrapChunkTimeout marks a chunk-fetch failure as our own
// synthesized timeout (bootstrap_chunk_request_timeout elapsed with no
// response), as opposed to a real error the connection itself reported.
// Wrapped with %w at each site that produces it, so handle_failure can
// recognize it through errors.Is regardless of how much additional context
// gets layered on around it (e.g. attempt_fetch_sc's "SC data-tree fetch
// from %s: %w").
var errBootstrapChunkTimeout = errors.New("timed out waiting for a response")

// handle_failure decides whether a chunk-fetch failure against failed_peer
// should take the peer out of the live pool entirely, or just cost it this
// one chunk. rpc2.Client multiplexes many concurrent requests over one
// connection, and our fan-out fires dozens of chunk requests to the same
// peer at once - a bare timeout on ONE of those doesn't mean the peer is
// dead, just that one particular request was slow (confirmed live: a peer
// logged a chunk timeout and a successful fetch in the same second). Only a
// genuine connection-level error (closed pipe, reset, shut down - the
// connection itself reporting it's broken) drops the peer immediately.
// Repeated bare timeouts against the same peer still drop it eventually
// (bootstrap_peer_timeout_drop_threshold), since a peer that's chronically
// slow rather than momentarily busy needs the same treatment a hard error
// would get.
func (p *bootstrap_live_peer_pool) handle_failure(failed_peer *Connection, cause error) (dropped bool, reason string) {
	addr := failed_peer.Addr.String()
	if errors.Is(cause, errBootstrapChunkTimeout) {
		p.mu.Lock()
		if p.timeout_counts == nil {
			p.timeout_counts = map[string]int{}
		}
		p.timeout_counts[addr]++
		count := p.timeout_counts[addr]
		p.mu.Unlock()
		if count < bootstrap_peer_timeout_drop_threshold {
			return false, ""
		}
		reason = fmt.Sprintf("timed out %d times", count)
	} else {
		reason = cause.Error()
	}
	failed_peer.exit()
	// mark_dead's own return, not an unconditional true, is what decides
	// dropped here: our fan-out fires many concurrent requests per peer, so
	// a connection that actually dies produces a burst of near-simultaneous
	// failures against it, each reaching handle_failure independently -
	// live-caught: 2061 log lines for only 18 real drops before this fix.
	// Only the call that actually performs the removal should be reported
	// as a drop; every later one against an already-gone peer is a no-op.
	return p.mark_dead(addr), reason
}

// bootstrap_spot_check_sample_rate: 1-in-N chunks get re-checked against a
// second peer. Bounded overhead proportional to sample rate, not total
// chunk count - the whole point versus full per-chunk quorum.
const bootstrap_spot_check_sample_rate = 10

// bootstrap_spot_check_retry_delay: how long to wait before re-checking a
// mismatched chunk, giving an in-flight commit/finalization window time to
// clear. Grounded in this session's own live-reproduced case, not a guess -
// a getsc read returned a stale value for a few seconds during our own
// node's commit finalization, then self-corrected with no code change in
// between. Distinct from bootstrap_chunk_request_timeout's own reasoning
// (that's inter-completion gaps under normal fetch load - a different
// phenomenon), so a separate constant rather than reusing that value.
const bootstrap_spot_check_retry_delay = 2 * time.Second

// bootstrap_spot_check_classify decides whether two fresh, independent
// re-reads of the same chunk agree (the original mismatch was transient) or
// still disagree (a confirmed, real signal). Factored out as a pure
// function so this decision is unit-testable without mocking rpc2/network
// I/O - see bootstrap_quorum_test.go.
func bootstrap_spot_check_classify(retry_hash_a, retry_hash_b [32]byte) (resolved bool) {
	return retry_hash_a == retry_hash_b
}

// bootstrap_chunk_request_timeout bounds how long a single TreeSection
// request (balance tree, SC-meta outer, per-SC, per-SC continuation) waits
// for a response before being treated as a failure and retried on a
// different peer. Chosen from real observed data, not a guess: parsed
// per-peer inter-completion gaps from a live run's console log (3868
// events, 17 peers) - max observed legitimate gap was 9s, p99 2s, p95 1s,
// median 0s. 30s is roughly 3x the worst observed legitimate gap, well
// past typical, while still bounding a stall to a small fraction of the
// multi-minute-plus hangs actually observed live without any timeout at
// all. A peer that accepts a request but never responds (no error, no
// close) previously blocked its result's drain loop forever - since
// results are drained one at a time per chunk, that stalled the whole
// phase, not just the one chunk.
const bootstrap_chunk_request_timeout = 30 * time.Second

// bootstrap_sc_progress_tick_interval bounds how long step 2's nested
// per-SC data-tree fetch can stay silent at default log verbosity. Its
// drain loop (in bootstrap_chain) only advances the visible percent once
// an entire outer SC-meta chunk - every SC discovered in it, including any
// single huge SC's own sequential continuation-chunk fetch - finishes, so
// without this an operator has no signal at all during that window short
// of raising verbosity into per-chunk noise or a fatal SIGQUIT dump
// (live-observed: an 8-minute silent gap, confirmed real and bounded only
// via a goroutine dump). 20s split the difference between "frequent enough
// that an operator isn't left guessing" and "rare enough to stay
// low-volume" - well under bootstrap_chunk_request_timeout so a tick can
// still land even while a single request is the thing in flight.
const bootstrap_sc_progress_tick_interval = 20 * time.Second

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

	// Picking the first non-answering peer in peers' fixed order (as this
	// used to) means, in practice, almost always the SAME single checker
	// for the whole run - peers is a static snapshot, not reshuffled per
	// call. Live-caught: 98.3% of one run's spot-checks (4967 of 5052)
	// used one identical checker. That defeats the whole point - a single
	// bad/stale checker makes every answerer it's paired against look
	// like it disagrees, indistinguishable from genuinely catching a bad
	// answerer. Picking uniformly among all non-answering candidates
	// instead means no single peer's own state can systematically bias
	// every check's outcome.
	candidates := make([]*Connection, 0, len(peers))
	for _, p := range peers {
		if p != answered_by {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) == 0 {
		return
	}
	checker := candidates[rand.Intn(len(candidates))]

	go func() {
		ts_request := Request_Tree_Section_Struct{Topo: topo, TreeName: []byte(tree_name), Section: section, SectionLength: section_length}
		fill_common(&ts_request.Common)
		var ts_response Response_Tree_Section_Struct
		if err := checker.Client.Call("Peer.TreeSection", ts_request, &ts_response); err != nil {
			logger.V(2).Info("bootstrap spot-check: re-fetch failed, skipping", "chunk", chunk_desc, "checker", checker.Addr.String(), "err", err)
			return
		}
		// Latency included directly on both log lines so a live run can
		// test whether disagreement correlates with peer speed (e.g. the
		// fastest/most-selected peers being the ones most often involved)
		// without needing to cross-reference against separate progress logs.
		answered_by_latency := atomic.LoadInt64(&answered_by.Latency)
		checker_latency := atomic.LoadInt64(&checker.Latency)
		if hash_tree_section_response(&ts_response) != hash_tree_section_response(original) {
			// A single mismatch here does NOT mean the chain's real state
			// disagrees - live-investigated at length: full contract
			// content (variables, code, balance) matched byte-for-byte
			// across 14+ independent peers, at both current tip and the
			// exact pinned historical topoheight bootstrap used, and the
			// network's whole-state Merkle treehash matched across 10
			// independent peers too. We separately reproduced the actual
			// mechanism live: a getsc read returned a stale value for a
			// few seconds during our own node's commit finalization, then
			// self-corrected with no code change in between. So a first
			// mismatch is treated as likely-transient noise, not logged as
			// a confirmed disagreement - only escalated if it survives a
			// retry against BOTH sides fresh (see below).
			logger.V(1).Info("bootstrap spot-check: mismatch, retrying", "chunk", chunk_desc, "answered_by", answered_by.Addr.String(), "answered_by_latency", answered_by_latency, "checked_by", checker.Addr.String(), "checked_by_latency", checker_latency)

			time.Sleep(bootstrap_spot_check_retry_delay)

			retry_request := Request_Tree_Section_Struct{Topo: topo, TreeName: []byte(tree_name), Section: section, SectionLength: section_length}
			fill_common(&retry_request.Common)
			var retry_a, retry_b Response_Tree_Section_Struct
			err_a := answered_by.Client.Call("Peer.TreeSection", retry_request, &retry_a)
			err_b := checker.Client.Call("Peer.TreeSection", retry_request, &retry_b)
			if err_a != nil || err_b != nil {
				logger.V(1).Info("bootstrap spot-check: retry inconclusive (re-fetch failed), not escalating", "chunk", chunk_desc, "answered_by_err", err_a, "checked_by_err", err_b)
				return
			}

			// Compare the two FRESH reads to each other, never a fresh
			// read against either original response - either side could
			// have been the one that hit the transient race, so neither
			// original response is trustworthy enough to anchor against.
			if bootstrap_spot_check_classify(hash_tree_section_response(&retry_a), hash_tree_section_response(&retry_b)) {
				logger.V(1).Info("bootstrap spot-check: mismatch resolved on retry (transient)", "chunk", chunk_desc, "answered_by", answered_by.Addr.String(), "checked_by", checker.Addr.String())
				return
			}

			// Key counts and edge keys included since a CONFIRMED
			// disagreement should now be a genuinely rare event (the
			// dominant real cause - a shared, mutated-in-place section
			// buffer read late by this goroutine - was found and fixed in
			// chain_bootstrap.go's per-SC continuation loop) - if one
			// still occurs, this is enough detail to tell truncation
			// (10,000-key response cap) apart from a real key-set or
			// value difference without a second investigation from scratch.
			var first_a, last_a, first_b, last_b string
			if len(retry_a.Keys) > 0 {
				first_a = fmt.Sprintf("%x", retry_a.Keys[0])
				last_a = fmt.Sprintf("%x", retry_a.Keys[len(retry_a.Keys)-1])
			}
			if len(retry_b.Keys) > 0 {
				first_b = fmt.Sprintf("%x", retry_b.Keys[0])
				last_b = fmt.Sprintf("%x", retry_b.Keys[len(retry_b.Keys)-1])
			}
			logger.Error(nil, "bootstrap spot-check: CONFIRMED disagreement after retry", "chunk", chunk_desc, "answered_by", answered_by.Addr.String(), "answered_by_latency", answered_by_latency, "checked_by", checker.Addr.String(), "checked_by_latency", checker_latency, "a_keycount", len(retry_a.Keys), "a_first_key", first_a, "a_last_key", last_a, "b_keycount", len(retry_b.Keys), "b_first_key", first_b, "b_last_key", last_b)
			return
		}
		logger.V(3).Info("bootstrap spot-check: peers agree", "chunk", chunk_desc, "answered_by", answered_by.Addr.String(), "answered_by_latency", answered_by_latency, "checked_by", checker.Addr.String(), "checked_by_latency", checker_latency)
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
// actual log rather than assuming the fix worked).
var bootstrap_warmup_done bool

// bootstrap_warmup_wait lets the real peer pool grow before the manifest
// tier decision fires. Real observation: trigger_sync fires the first
// bootstrap attempt only ~5-6 seconds after P2P startup, on whatever tiny
// connection count exists at that instant - not because enough real peers
// don't exist, but because nothing ever waited for them.
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

	// tier 3: a trusted peer if one is connected and eligible - still a
	// single, unverified source (no quorum agreement backs this response),
	// but at least an operator-configured one rather than whichever peer
	// happened to be picked automatically.
	for _, c := range eligible {
		if is_trusted_peer(c) {
			logger.Info("fetch_bootstrap_manifest: quorum NOT possible (too few eligible peers) - using a single OPERATOR-CONFIGURED TRUSTED peer, no cross-peer verification for this fetch", "addr", c.Addr.String())
			var response Changes
			r := request
			fill_common(&r.Common)
			if err := c.Client.Call("Peer.ChangeSet", r, &response); err == nil {
				return &response, c, nil
			}
		}
	}

	// ultimate fallback: today's original, unchanged behavior - a single
	// peer with NO quorum agreement and NO operator trust configuration at
	// all backing it. This is the real, structural gap this cycle's own
	// obstacles concluded can't be fixed by spot-checking or quorum (both
	// need a second peer, which is exactly what this path means the
	// absence of) - made loud deliberately, not silently accepted.
	logger.Error(nil, "fetch_bootstrap_manifest: UNVERIFIED single-peer fallback - no quorum, no trusted peer available, accepting manifest data from one automatically-chosen peer with no cross-verification of any kind", "addr", fallback_connection.Addr.String())
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
