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
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/cenkalti/rpc2"
	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto" //import "net"
	"github.com/deroproject/derohe/transaction"
	"github.com/deroproject/graviton"
)

//import "github.com/deroproject/derohe/errormsg"

//import "github.com/deroproject/derosuite/blockchain"

// we are expecting other side to have a heavier PoW chain
// this is for the case when the chain only moves in pruned state
// if after bootstraping the chain can continousky sync for few minutes, this means we have got the job done

type sync_progress struct {
	Step   uint
	Chunk  int64
	Height int64
}

var state sync_progress

func (connection *Connection) bootstrap_fail(msg error) {
	// Does NOT drop `connection` here - `connection` is whichever peer
	// trigger_sync originally called bootstrap_chain() on, but
	// bootstrap_chain() reassigns internally to a quorum-chosen peer and
	// fans chunk-fetch out across still more peers, so by the time an
	// error reaches here, `connection` is very often not who actually
	// failed. Dropping it anyway produces a self-perpetuating cascade -
	// each tick drops an unrelated, healthy peer one step behind the real
	// failure, which then gets picked up as a fan-out peer on the next
	// tick and fails immediately since it had just been closed. Whichever
	// peer genuinely failed is dropped at its own point of failure inside
	// bootstrap_chain(), where the real reference is still known - see the
	// .exit() calls next to each TreeSection/manifest
	// error return there.
	connection.logger.Error(msg, "Bootstrap attempt failed - will retry with a different peer on the next tick")
}

func (connection *Connection) bootstrap_chain() error {
	defer handle_connection_panic(connection)
	var request ChangeList
	var response Changes
	var err error
	var zerohash crypto.Hash

	// peer's chain is only 110 height, so do not bootstrap
	if connection.TopoHeight-50-max_request_topoheights < 10 {
		connection.logger.Info("fastsync cannot be done as peer's chain has low height")
		connection.logger.Info("will do normal sync")
		connection.sync_chain()
		return nil
	}

	if state.Height == 0 {
		state.Height = connection.TopoHeight
		state.Step = 1
	}

	// we will request top 60 blocks
	ctopo := state.Height - 50 // last 50 blocks have to be synced, this syncing will help us detect error
	var topos []int64
	for i := ctopo - (max_request_topoheights - 1); i < ctopo; i++ {
		topos = append(topos, i)
	}

	for i := range topos {
		request.TopoHeights = append(request.TopoHeights, topos[i])
	}

	// Tiered trust-minimized manifest fetch (swarm quorum -> proportional
	// quorum -> trusted peer -> original single-peer behavior as the
	// ultimate fallback), instead of blindly trusting whichever single peer
	// trigger_sync happened to pick. connection is reassigned to whichever
	// peer was actually used, so the rest of this function's (unchanged)
	// chunk-fetching uses a peer that's now proven to agree with the
	// quorum, not an unverified single source.
	manifest, chosen_connection, ferr := fetch_bootstrap_manifest(connection, request)
	if ferr != nil {
		return ferr
	}
	response = *manifest
	connection = chosen_connection
	// "Bootstrap Initiated" logs here, after the reassignment above, so it
	// and every subsequent per-step log in this function share the same
	// peer address - logging it before the reassignment made it look like
	// two different peers were handling one bootstrap run, when it was
	// really the same run continuing on the peer the quorum settled on.
	connection.logger.Info("Bootstrap Initiated")
	connection.logger.V(1).Info("changeset received (tiered manifest fetch)", "keycount", response.KeyCount, "sccount", response.SCKeyCount)

	commit_version := uint64(0)

	// pipeline a window of concurrent TreeSection requests instead of
	// waiting for each chunk's round-trip before firing the next one.
	// results are drained in COMPLETION order (not index order) so one slow
	// chunk can't head-of-line-block chunks that already finished -- chunk
	// writes are commutative (disjoint key ranges into the same tree), so
	// there is no ordering requirement here, unlike sync_chain's block adds.
	pipeline, threads := 0, runtime.GOMAXPROCS(0) // N.B. Optimize by profiling hardware
	switch {
	case threads < 1:
		pipeline = 1
	case threads > 32:
		pipeline = 32
	default:
		pipeline = threads
	}

	{ // fetch and commit balance tree

		chunksize := int64(640)
		chunks_estm := response.KeyCount / chunksize
		chunks := int64(1) // chunks need to be in power of 2
		path_length := 0
		for chunks < chunks_estm {
			chunks = chunks * 2
			path_length++
		}

		if chunks < 2 {
			chunks = 2
			path_length = 1
		}

		total_keys := 0

		if state.Step < 2 {

			// Fan the chunk fetch itself across every eligible peer, not just
			// the single quorum-chosen connection - reuses the same
			// target-based eligibility already proven for the manifest
			// quorum. round_robin(i) picks a peer per chunk index; with
			// requests already fired ahead and drained in completion order
			// (below), a chunk assigned to a slower peer just completes
			// later rather than blocking anything, so this gets most of the
			// benefit of real work-stealing without needing to build a
			// second dispatcher alongside run_fanout_dispatch's proven one
			// (which is shaped for block fetch, not chunk fetch, and stays
			// untouched here).
			fanout_peers := bootstrap_chunk_fanout_peers(connection, request.TopoHeights[0])

			// fanout_peers is a fixed snapshot for this whole phase - as its
			// peers die off over what can be several minutes, known_dead
			// lets one chunk's discovery immediately help every other
			// chunk, instead of each independently re-learning the same
			// dead peer through its own (per-chunk) already_tried
			// exclusion. See bootstrap_known_dead_peers's own doc comment.
			known_dead := new_bootstrap_known_dead_peers()
			round_robin := func(i int64) *Connection {
				n := int64(len(fanout_peers))
				for attempt := int64(0); attempt < n; attempt++ {
					p := fanout_peers[(i+attempt)%n]
					if !known_dead.is_dead(p.Addr.String()) {
						return p
					}
				}
				// everyone's dead - fall back to the plain modulo pick
				// anyway; the retry path will discover it's dead too and
				// either find a survivor or genuinely give up, same as
				// before this fix.
				return fanout_peers[i%n]
			}

			// Scale the in-flight request budget with the number of fan-out
			// peers, not one fixed window shared across all of them.
			// `pipeline` alone is sized for a single peer's optimal
			// concurrency (GOMAXPROCS-based) - dividing that same window
			// across N peers via round-robin meant each peer only had
			// ~1/N requests in flight on average, which isn't torrent-like
			// fan-out, just a small window spread thin. Confirmed live: with
			// the shared window of 16 spread across ~30 real peers, the
			// resumable watermark advanced roughly 20x slower than
			// pipelining that same 16 to a single peer. Each fan-out peer
			// now gets its own full `pipeline`-sized window instead - the
			// round-robin assignment below already cycles evenly through
			// all N peers, so firing total_pipeline requests ahead gives
			// each peer ~pipeline of them, same per-peer concurrency this
			// was already proven safe at, just no longer divided.
			total_pipeline := int64(pipeline) * int64(len(fanout_peers))

			type indexed_result struct {
				index int64
				call  *rpc2.Call
				peer  *Connection
			}
			results := make(chan indexed_result, total_pipeline)

			do_fire := func(i int64, peer *Connection) {
				var section [8]byte
				binary.BigEndian.PutUint64(section[:], bits.Reverse64(uint64(i))) // place reverse path
				ts_request := &Request_Tree_Section_Struct{Topo: request.TopoHeights[0], TreeName: []byte(config.BALANCE_TREE), Section: section[:], SectionLength: uint64(path_length)}
				fill_common(&ts_request.Common)
				done := make(chan *rpc2.Call, 1)
				call := peer.Client.Go("Peer.TreeSection", ts_request, &Response_Tree_Section_Struct{}, done)
				go func() {
					<-done
					results <- indexed_result{index: i, call: call, peer: peer}
				}()
			}
			fire := func(i int64) { do_fire(i, round_robin(i)) }

			next_fire := state.Chunk
			inflight_count := int64(0)
			for ; next_fire < chunks && inflight_count < total_pipeline; next_fire++ {
				fire(next_fire)
				inflight_count++
			}

			// On a chunk-fetch failure, retry that SAME chunk against a
			// different eligible peer instead of aborting the whole
			// attempt - one flaky peer among many fan-out peers used to
			// kill the entire bootstrap run, and at the concurrency levels
			// fan-out now runs at, at least one request failing at any
			// given moment is close to certain (confirmed live: dozens of
			// closed-pipe/timeout errors per minute against ~30 real
			// peers). already_tried is keyed per chunk index, not global,
			// so a peer that failed one chunk can still serve others.
			// Retrying re-fires into the very in-flight slot the failure
			// vacated - inflight_count nets to unchanged, no extra budget
			// needed. Only once every eligible peer has been tried for a
			// specific chunk does this give up and abort the attempt, same
			// as before, just now the rare last resort instead of the
			// first failure.
			already_tried := map[int64]map[string]bool{}
			retry_or_give_up := func(idx int64, failed_peer *Connection, cause error) (retried bool, err error) {
				failed_peer.exit()
				known_dead.mark(failed_peer.Addr.String())
				if already_tried[idx] == nil {
					already_tried[idx] = map[string]bool{}
				}
				already_tried[idx][failed_peer.Addr.String()] = true
				if alt := pick_alternate_chunk_peer(fanout_peers, already_tried[idx], known_dead); alt != nil {
					alt.logger.V(2).Info("retrying balance-tree chunk on alternate peer", "index", idx, "failed_peer", failed_peer.Addr.String(), "cause", cause)
					do_fire(idx, alt)
					inflight_count++
					return true, nil
				}
				return false, fmt.Errorf("balance-tree chunk %d exhausted all eligible peers: %w", idx, cause)
			}

			completed := make(map[int64]bool)
			low_water_mark := state.Chunk
			total_to_do := chunks - state.Chunk

			for done_count := int64(0); done_count < total_to_do; {
				res := <-results
				inflight_count--
				if res.call.Error != nil {
					if retried, giveup_err := retry_or_give_up(res.index, res.peer, res.call.Error); retried {
						continue
					} else {
						return giveup_err
					}
				}
				ts_response := res.call.Reply.(*Response_Tree_Section_Struct)
				res.peer.logger.V(2).Info("served balance-tree chunk", "index", res.index)

				{
					var spot_section [8]byte
					binary.BigEndian.PutUint64(spot_section[:], bits.Reverse64(uint64(res.index)))
					bootstrap_spot_check_chunk(fanout_peers, res.peer, ts_response, config.BALANCE_TREE, request.TopoHeights[0], spot_section[:], uint64(path_length), fmt.Sprintf("balance-tree chunk %d", res.index))
				}

				// now we must write all the state changes to gravition
				var balance_tree *graviton.Tree
				if ss, err := chain.Store.Balance_store.LoadSnapshot(0); err != nil {
					panic(err)
				} else if balance_tree, err = ss.GetTree(config.BALANCE_TREE); err != nil {
					panic(err)
				}

				if len(ts_response.Keys) != len(ts_response.Values) {
					//rlog.Warnf("Incoming Key count %d value count %d \"%s\" ", len(ts_response.Keys), len(ts_response.Values), globals.CTXString(connection.logger))
					if retried, giveup_err := retry_or_give_up(res.index, res.peer, fmt.Errorf("mismatched key and value count")); retried {
						continue
					} else {
						return giveup_err
					}
				}
				//rlog.Debugf("chunk %d Will write %d keys\n", res.index, len(ts_response.Keys))

				for j := range ts_response.Keys {
					balance_tree.Put(ts_response.Keys[j], ts_response.Values[j])
				}
				total_keys += len(ts_response.Keys)

				commit_version, err = graviton.Commit(balance_tree)
				if err != nil {
					panic(err)
				}

				h, err := balance_tree.Hash()
				_ = h
				_ = err
				//rlog.Debugf("total keys %d hash %x err %s\n", total_keys, h, err)

				completed[res.index] = true
				prev_water_mark := low_water_mark
				for completed[low_water_mark] {
					delete(completed, low_water_mark)
					low_water_mark++
				}
				state.Chunk = low_water_mark
				// log the watermark (contiguous, resumable progress), not
				// res.index (whichever chunk just happened to complete) -
				// with chunks fanned across peers of differing latency,
				// completion order jumps around a lot more than index order
				// does, so res.index made the percent field visibly
				// non-monotonic. Only log when the watermark actually moves,
				// both to keep this meaningful and to avoid a log line per
				// out-of-order completion that doesn't represent new
				// resumable progress.
				if low_water_mark != prev_water_mark {
					connection.logger.Info("Bootstrap in progress(step1)", "percent", float32(low_water_mark*100)/float32(chunks))
				}
				done_count++

				if next_fire < chunks {
					fire(next_fire)
					next_fire++
					inflight_count++
				}
			}
			state.Step = 2
			state.Chunk = 0
		}
	}

	{ // fetch and commit SC tree
		chunksize := int64(640)
		chunks_estm := response.SCKeyCount / chunksize
		chunks := int64(1) // chunks need to be in power of 2
		path_length := 0
		for chunks < chunks_estm {
			chunks = chunks * 2
			path_length++
		}

		if chunks < 2 {
			chunks = 2
			path_length = 1
		}

		total_keys := 0

		// Fan the SC-meta chunk fetch across eligible peers too - same
		// pattern as the balance tree above. Recomputed fresh here rather
		// than reusing the balance tree's peer list: step 2 runs for
		// several more minutes than step 1, long enough for the real peer
		// pool to have changed since step 1 started.
		fanout_peers := bootstrap_chunk_fanout_peers(connection, request.TopoHeights[0])

		// Same known_dead sharing as the balance tree above - this phase's
		// own instance, shared by the outer SC-meta fetch below AND its
		// nested per-SC fetches, since both draw from this same
		// fanout_peers snapshot and run concurrently over the same span.
		known_dead := new_bootstrap_known_dead_peers()
		round_robin := func(i int64) *Connection {
			n := int64(len(fanout_peers))
			for attempt := int64(0); attempt < n; attempt++ {
				p := fanout_peers[(i+attempt)%n]
				if !known_dead.is_dead(p.Addr.String()) {
					return p
				}
			}
			return fanout_peers[i%n]
		}

		// pipeline the OUTER SC-meta chunk fetch too (same fire-ahead pattern
		// as the balance tree above): this loop was left fully sequential
		// (one blocking Client.Call per chunk) when the balance-tree loop
		// and the nested per-SC fetches below were pipelined, making step 2
		// visibly slower per-unit than step 1.
		//
		// Deliberately a SEPARATE, SMALLER per-peer window than `pipeline`
		// (capped at 4), not reusing it directly: each outer chunk here also
		// spins up its own nested per-SC pipeline (up to `pipeline`
		// concurrent requests) below. An unbounded per-peer outer window
		// would compound against that nested one (outer x inner) on
		// whichever peer answers both. Scaled by peer count for the same
		// torrent-like reason as the balance tree above - each fan-out peer
		// keeps its own bounded share (4) rather than the total staying
		// fixed regardless of how many peers are available - but the
		// PER-PEER cap itself stays at 4, not `pipeline`, so the
		// compounding risk this was written to avoid doesn't come back in
		// fan-out form.
		outer_pipeline_per_peer := int64(pipeline)
		if outer_pipeline_per_peer > 4 {
			outer_pipeline_per_peer = 4
		}
		outer_pipeline := outer_pipeline_per_peer * int64(len(fanout_peers))

		type sc_meta_indexed_result struct {
			index int64
			call  *rpc2.Call
			peer  *Connection
		}
		sc_meta_results := make(chan sc_meta_indexed_result, outer_pipeline)

		do_fire_sc_meta := func(i int64, peer *Connection) {
			var section [8]byte
			binary.BigEndian.PutUint64(section[:], bits.Reverse64(uint64(i))) // place reverse path
			ts_request := &Request_Tree_Section_Struct{Topo: request.TopoHeights[0], TreeName: []byte(config.SC_META), Section: section[:], SectionLength: uint64(path_length)}
			fill_common(&ts_request.Common)
			done := make(chan *rpc2.Call, 1)
			call := peer.Client.Go("Peer.TreeSection", ts_request, &Response_Tree_Section_Struct{}, done)
			go func() {
				<-done
				sc_meta_results <- sc_meta_indexed_result{index: i, call: call, peer: peer}
			}()
		}
		fire_sc_meta := func(i int64) { do_fire_sc_meta(i, round_robin(i)) }

		next_fire := state.Chunk
		inflight_count := int64(0)
		for ; next_fire < chunks && inflight_count < outer_pipeline; next_fire++ {
			fire_sc_meta(next_fire)
			inflight_count++
		}

		// Same retry-on-alternate-peer pattern as the balance tree above -
		// see that block's comment for the full reasoning.
		already_tried_sc_meta := map[int64]map[string]bool{}
		retry_or_give_up_sc_meta := func(idx int64, failed_peer *Connection, cause error) (retried bool, err error) {
			failed_peer.exit()
			known_dead.mark(failed_peer.Addr.String())
			if already_tried_sc_meta[idx] == nil {
				already_tried_sc_meta[idx] = map[string]bool{}
			}
			already_tried_sc_meta[idx][failed_peer.Addr.String()] = true
			if alt := pick_alternate_chunk_peer(fanout_peers, already_tried_sc_meta[idx], known_dead); alt != nil {
				alt.logger.V(2).Info("retrying SC-meta chunk on alternate peer", "index", idx, "failed_peer", failed_peer.Addr.String(), "cause", cause)
				do_fire_sc_meta(idx, alt)
				inflight_count++
				return true, nil
			}
			return false, fmt.Errorf("SC-meta chunk %d exhausted all eligible peers: %w", idx, cause)
		}

		completed := make(map[int64]bool)
		low_water_mark := state.Chunk
		total_to_do := chunks - state.Chunk

		for done_count := int64(0); done_count < total_to_do; {
			res := <-sc_meta_results
			inflight_count--
			if res.call.Error != nil {
				if retried, giveup_err := retry_or_give_up_sc_meta(res.index, res.peer, res.call.Error); retried {
					continue
				} else {
					return giveup_err
				}
			}
			ts_response := *res.call.Reply.(*Response_Tree_Section_Struct)
			i := res.index
			res.peer.logger.V(2).Info("served SC-meta chunk", "index", i)

			{
				var spot_section [8]byte
				binary.BigEndian.PutUint64(spot_section[:], bits.Reverse64(uint64(i)))
				bootstrap_spot_check_chunk(fanout_peers, res.peer, &ts_response, config.SC_META, request.TopoHeights[0], spot_section[:], uint64(path_length), fmt.Sprintf("SC-meta chunk %d", i))
			}
			{
				// now we must write all the state changes to gravition
				var changed_trees []*graviton.Tree
				var sc_tree *graviton.Tree
				//var changed_trees []*graviton.Tree
				ss, err := chain.Store.Balance_store.LoadSnapshot(0)
				if err != nil {
					panic(err)
				} else if sc_tree, err = ss.GetTree(config.SC_META); err != nil {
					panic(err)
				}

				if len(ts_response.Keys) != len(ts_response.Values) {
					//rlog.Warnf("Incoming Key count %d value count %d \"%s\" ", len(ts_response.Keys), len(ts_response.Values), globals.CTXString(connection.logger))
					if retried, giveup_err := retry_or_give_up_sc_meta(res.index, res.peer, fmt.Errorf("mismatched key and value count")); retried {
						continue
					} else {
						return giveup_err
					}
				}
				//rlog.Debugf("SC chunk %d Will write %d keys\n", i, len(ts_response.Keys))

				for j := range ts_response.Keys {
					sc_tree.Put(ts_response.Keys[j], ts_response.Values[j])
				}

				// fetch each discovered SC's own data tree concurrently instead of one at a
				// time -- only the network round-trips run in worker goroutines (already
				// proven safe for concurrent use by rpc2.Client); every graviton GetTree/Put
				// call stays on this single goroutine, so there's no concurrent access to
				// graviton's Snapshot/Tree at all, just parallel network I/O
				type sc_fetch_result struct {
					key          []byte
					keys, values [][]byte
					err          error
				}

				// One attempt at a whole SC's data tree (including any of its
				// own continuation chunks for large SCs) against a specific
				// peer - no retry logic here, that's fetch_one_sc's job below.
				attempt_fetch_sc := func(key []byte, peer *Connection) sc_fetch_result {
					var section [8]byte
					sc_request := Request_Tree_Section_Struct{Topo: request.TopoHeights[0], TreeName: key, Section: section[:], SectionLength: uint64(0)}
					var sc_response Response_Tree_Section_Struct
					fill_common(&sc_request.Common)
					if err := peer.Client.Call("Peer.TreeSection", sc_request, &sc_response); err != nil {
						return sc_fetch_result{key: key, err: fmt.Errorf("SC data-tree fetch from %s: %w", peer.Addr.String(), err)}
					}

					if sc_response.KeyCount < 4096 {
						peer.logger.V(3).Info("served SC data-tree fetch", "key", fmt.Sprintf("%x", key))
						return sc_fetch_result{key: key, keys: sc_response.Keys, values: sc_response.Values}
					}

					// huge tree -- fetch remaining chunks sequentially within this goroutine
					// (still only network calls; still no graviton access here)
					sc_chunks_estm := sc_response.KeyCount / chunksize
					sc_chunks := int64(1) // chunks need to be in power of 2
					sc_path_length := 0
					for sc_chunks < sc_chunks_estm {
						sc_chunks = sc_chunks * 2
						sc_path_length++
					}

					if sc_chunks < 2 {
						sc_chunks = 2
						sc_path_length = 1
					}

					all_keys := append([][]byte{}, sc_response.Keys...)
					all_values := append([][]byte{}, sc_response.Values...)

					var sc_section [8]byte
					for k := int64(0); k < sc_chunks; k++ {
						binary.BigEndian.PutUint64(sc_section[:], bits.Reverse64(uint64(k))) // place reverse path
						sc_ts_request := Request_Tree_Section_Struct{Topo: request.TopoHeights[0], TreeName: key, Section: sc_section[:], SectionLength: uint64(sc_path_length)}
						var sc_ts_response Response_Tree_Section_Struct
						fill_common(&sc_ts_request.Common)
						if err := peer.Client.Call("Peer.TreeSection", sc_ts_request, &sc_ts_response); err != nil {
							return sc_fetch_result{key: key, err: fmt.Errorf("SC data-tree continuation fetch from %s: %w", peer.Addr.String(), err)}
						}
						if len(sc_ts_response.Keys) != len(sc_ts_response.Values) {
							return sc_fetch_result{key: key, err: fmt.Errorf("mismatched key and value count")}
						}
						all_keys = append(all_keys, sc_ts_response.Keys...)
						all_values = append(all_values, sc_ts_response.Values...)
					}
					peer.logger.V(3).Info("served SC data-tree fetch", "key", fmt.Sprintf("%x", key))
					return sc_fetch_result{key: key, keys: all_keys, values: all_values}
				}

				// idx picks the first peer to try (round_robin, same pool as
				// the outer SC-meta fetch). On failure, retry the whole SC
				// (including any continuation chunks) against a different
				// untried eligible peer, same retry-on-alternate-peer pattern
				// as the balance tree and SC-meta outer loop above - self
				// contained here since this whole call already runs in its
				// own goroutine, so there's no outer drain-loop bookkeeping
				// to coordinate with.
				fetch_one_sc := func(idx int, key []byte) sc_fetch_result {
					peer := round_robin(int64(idx))
					already_tried := map[string]bool{}
					for {
						res := attempt_fetch_sc(key, peer)
						if res.err == nil {
							return res
						}
						failed_peer := peer
						failed_peer.exit()
						known_dead.mark(failed_peer.Addr.String())
						already_tried[failed_peer.Addr.String()] = true
						alt := pick_alternate_chunk_peer(fanout_peers, already_tried, known_dead)
						if alt == nil {
							return res
						}
						alt.logger.V(3).Info("retrying SC data-tree fetch on alternate peer", "key", fmt.Sprintf("%x", key), "failed_peer", failed_peer.Addr.String(), "cause", res.err)
						peer = alt
					}
				}

				sc_results := make(chan sc_fetch_result, pipeline)
				launch := func(idx int) {
					go func() { sc_results <- fetch_one_sc(idx, ts_response.Keys[idx]) }()
				}

				sc_next := 0
				sc_inflight := 0
				sc_pipeline := int(pipeline)
				for ; sc_next < len(ts_response.Keys) && sc_inflight < sc_pipeline; sc_next++ {
					launch(sc_next)
					sc_inflight++
				}

				for done := 0; done < len(ts_response.Keys); done++ {
					res := <-sc_results
					sc_inflight--
					if res.err != nil {
						return res.err
					}

					sc_data_tree, terr := ss.GetTree(string(res.key))
					if terr != nil {
						panic(terr)
					}
					for k := range res.keys {
						sc_data_tree.Put(res.keys[k], res.values[k])
					}
					changed_trees = append(changed_trees, sc_data_tree)

					if sc_next < len(ts_response.Keys) {
						launch(sc_next)
						sc_next++
						sc_inflight++
					}
				}

				total_keys += len(ts_response.Keys)
				changed_trees = append(changed_trees, sc_tree)
				commit_version, err = graviton.Commit(changed_trees...)
				if err != nil {
					panic(err)
				}

				h, err := sc_tree.Hash()
				_ = h
				_ = err
				//rlog.Debugf("total SC keys %d hash %x err %s\n", total_keys, h, err)

			}

			completed[i] = true
			prev_water_mark := low_water_mark
			for completed[low_water_mark] {
				delete(completed, low_water_mark)
				low_water_mark++
			}
			state.Chunk = low_water_mark

			// same watermark-not-completion-index reasoning as step 1's log
			// site - see the comment there.
			if low_water_mark != prev_water_mark {
				connection.logger.Info("Bootstrap in progress(step 2)", "percent", float32(low_water_mark*100)/float32(chunks))
			}
			done_count++

			if next_fire < chunks {
				fire_sc_meta(next_fire)
				next_fire++
				inflight_count++
			}
		}
	}

	for i := int64(0); i <= request.TopoHeights[0]; i++ {
		chain.Store.Topo_store.Write(i, zerohash, commit_version, 0) // commit everything
	}
	chain.Store.Topo_store.Sync()

	for i := range response.CBlocks { // we must store the blocks

		var cbl block.Complete_Block // parse incoming block and deserialize it
		var bl block.Block
		// lets deserialize block first and see whether it is the requested object
		cbl.Bl = &bl
		err := bl.Deserialize(response.CBlocks[i].Block)
		if err != nil { // we have a block which could not be deserialized ban peer
			connection.logger.Error(err, "Error Incoming block could not be deserialised.")
			connection.exit()
			return nil
		}

		// give the chain some more time to respond
		atomic.StoreInt64(&connection.LastObjectRequestTime, time.Now().Unix())

		if i == 0 { // whatever datastore we have written, its state hash must match
			// ToDo

		}

		// complete the txs
		for j := range response.CBlocks[i].Txs {
			var tx transaction.Transaction
			err = tx.Deserialize(response.CBlocks[i].Txs[j])
			if err != nil { // we have a tx which could not be deserialized ban peer
				connection.logger.Error(err, "Error Incoming TX could not be deserialized")
				connection.exit()
				return nil
			}
			if bl.Tx_hashes[j] != tx.GetHash() {
				connection.logger.Error(err, "Error Incoming TX has mismatch.")
				connection.exit()
				return nil
			}

			cbl.Txs = append(cbl.Txs, &tx)
		}

		{ // first lets save all the txs, together with their link to this block as height
			for i := 0; i < len(cbl.Txs); i++ {
				if err = chain.Store.Block_tx_store.WriteTX(bl.Tx_hashes[i], cbl.Txs[i].Serialize()); err != nil {
					panic(err)
				}
			}
		}

		diff := new(big.Int)
		if _, ok := diff.SetString(response.CBlocks[i].Difficulty, 10); !ok { // if Cumulative_Difficulty could not be parsed, kill connection
			connection.logger.Error(fmt.Errorf("Could not Parse Difficulty in common"), "", "diff", response.CBlocks[i].Difficulty)
			connection.exit()
			return nil
		}

		// now we must write all the state changes to gravition

		var ss *graviton.Snapshot
		if ss, err = chain.Store.Balance_store.LoadSnapshot(0); err != nil {
			panic(err)
		}

		/*if len(response.CBlocks[i].Keys) != len(response.CBlocks[i].Values) {
			rlog.Warnf("Incoming Key count %d value count %d \"%s\" ", len(response.CBlocks[i].Keys), len(response.CBlocks[i].Values), globals.CTXString(connection.logger))
			connection.exit()
			return
		}*/

		write_count := 0
		commit_version := ss.GetVersion()
		if i != 0 {

			var changed_trees []*graviton.Tree

			for _, change := range response.CBlocks[i].Changes {
				var tree *graviton.Tree
				if tree, err = ss.GetTree(string(change.TreeName)); err != nil {
					panic(err)
				}

				for j := range change.Keys {
					tree.Put(change.Keys[j], change.Values[j])
					write_count++
				}
				changed_trees = append(changed_trees, tree)
			}
			commit_version, err = graviton.Commit(changed_trees...)
			if err != nil {
				panic(err)
			}
		}

		if err = chain.Store.Block_tx_store.WriteBlock(bl.GetHash(), bl.Serialize(), diff, commit_version, bl.Height); err != nil {
			panic(fmt.Sprintf("error while writing block"))
		}

		connection.logger.V(2).Info("Writing version", "topoheight", request.TopoHeights[i], "keycount", write_count, "commit version ", commit_version)

		chain.Store.Topo_store.Write(request.TopoHeights[i], bl.GetHash(), commit_version, int64(bl.Height)) // commit everything
	}

	connection.logger.Info("Bootstrap completed successfully.")
	// load the chain from the disk
	chain.Initialise_Chain_From_DB()
	chain.Sync = true
	return nil
}
