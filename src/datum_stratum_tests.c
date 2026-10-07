/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of CONVOY's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://convoy.xyz
 *
 * ---
 *
 * Copyright (c) 2025-2026 Bitcoin Ocean, LLC, Luke Dashjr, and individual contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "datum_conf.h"
#include "datum_coinbaser.h"
#include "datum_jsonrpc.h"
#include "datum_pow.h"
#include "datum_protocol.h"
#include "datum_protocol_internal.h"
#include "datum_stratum.h"
#include "datum_utils.h"

void stratum_calculate_merkle_branches(T_DATUM_STRATUM_JOB *s);
int client_mining_submit(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj);

static void datum_blake2b_refresh_time_offset_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB job;
	
	/* A job snapshots whether miners may submit a time offset. */
	memset(&tdata, 0, sizeof(tdata));
	memset(&job, 0, sizeof(job));
	job.block_template = &tdata;
	tdata.curtime = 2000000000;
	job.blake2b_flags = DATUM_BLAKE2B_USE_TIME_OFFSET;
	datum_stratum_job_refresh_blake2b(&job);
	datum_test(job.blake2b_time_on_wire == 2000000000u);
	datum_test(job.blake2b_flags == DATUM_BLAKE2B_USE_TIME_OFFSET);
	
	/* Without the flag the offset is ignored and curtime goes on the wire as is. */
	tdata.curtime = 2000000000;
	job.blake2b_flags = 0;
	datum_stratum_job_refresh_blake2b(&job);
	datum_test(job.blake2b_time_on_wire == 2000000000u);
	
	/* An unrepresentable base time clears the interpretation flag. */
	tdata.curtime = (uint64_t)UINT32_MAX + 1;
	job.blake2b_flags = DATUM_BLAKE2B_USE_TIME_OFFSET;
	datum_stratum_job_refresh_blake2b(&job);
	datum_test(job.blake2b_time_on_wire == (uint32_t)tdata.curtime);
	datum_test(job.blake2b_flags == 0);
}

static void datum_blake2b_client_pot_commitment_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB job;
	unsigned char c_ff[32], c_pot[32], c_variant[32], c_subsidy[32], c_local[32];
	unsigned char c_from_txn[32];
	unsigned char ff[39], pot[39];
	unsigned char cb_txn[64];
	size_t cb_len;
	
	memset(&tdata, 0, sizeof(tdata));
	memset(&job, 0, sizeof(job));
	tdata.version = 0x20000000;
	tdata.height = 12345;
	tdata.bits_uint = 0x1d00ffff;
	tdata.abw_enabled = true;
	tdata.abw_assignment_id = 1;
	datum_test(datum_blake2b_xor_key_hash(
		tdata.xor_key_hash, (const unsigned char[16]){0}));
	job.block_template = &tdata;
	job.is_datum_job = true;
	job.blake2b_time_on_wire = 1000;
	job.coinbase[0].coinb1_len = 20;
	job.coinbase[0].coinb2_len = 8;
	memset(job.coinbase[0].coinb1_bin, 0x11, 20);
	memset(job.coinbase[0].coinb2_bin, 0x22, 8);
	job.coinbase[0].coinb1_bin[4] = 0xFF;
	job.coinbase[2] = job.coinbase[0];
	job.coinbase[2].coinb2_bin[0] ^= 0x55;
	job.subsidy_only_coinbase = job.coinbase[0];
	job.subsidy_only_coinbase.coinb2_bin[0] ^= 0xaa;
	job.target_pot_index = 4;
	tdata.txn_count = 1;
	
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[0], false, 0xFF, c_ff, ff));
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[0], false, 14, c_pot, pot));
	datum_test(memcmp(c_ff, c_pot, 32) != 0);
	datum_test(memcmp(ff, pot, 39) != 0);
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.coinbase[2], false, 14, c_variant, NULL));
	datum_test(datum_stratum_job_blake2b_commitment(&job, &job.subsidy_only_coinbase, true, 14, c_subsidy, NULL));
	datum_test(memcmp(c_variant, c_pot, 32) != 0);
	datum_test(memcmp(c_subsidy, c_pot, 32) != 0);
	
	cb_len = (size_t)job.coinbase[0].coinb1_len + 12 + (size_t)job.coinbase[0].coinb2_len;
	memcpy(cb_txn, job.coinbase[0].coinb1_bin, job.coinbase[0].coinb1_len);
	memset(cb_txn + job.coinbase[0].coinb1_len, 0, 12);
	memcpy(cb_txn + job.coinbase[0].coinb1_len + 12, job.coinbase[0].coinb2_bin, job.coinbase[0].coinb2_len);
	cb_txn[job.target_pot_index] = 14;
	datum_test(datum_stratum_job_blake2b_commitment_from_txn(
		&job, cb_txn, cb_len, 14, false, c_from_txn));
	datum_test(!memcmp(c_from_txn, c_pot, 32));
	
	cb_len = (size_t)job.subsidy_only_coinbase.coinb1_len + 12 +
		(size_t)job.subsidy_only_coinbase.coinb2_len;
	memcpy(cb_txn, job.subsidy_only_coinbase.coinb1_bin,
		job.subsidy_only_coinbase.coinb1_len);
	memset(cb_txn + job.subsidy_only_coinbase.coinb1_len, 0, 12);
	memcpy(cb_txn + job.subsidy_only_coinbase.coinb1_len + 12,
		job.subsidy_only_coinbase.coinb2_bin,
		job.subsidy_only_coinbase.coinb2_len);
	cb_txn[job.target_pot_index] = 14;
	datum_test(datum_stratum_job_blake2b_commitment_from_txn(
		&job, cb_txn, cb_len, 14, true, c_from_txn));
	datum_test(!memcmp(c_from_txn, c_subsidy, 32));
	
	// Work without an assignment commits to the null XOR key.
	tdata.abw_enabled = false;
	tdata.abw_assignment_id = 0;
	job.is_datum_job = false;
	datum_test(datum_stratum_job_blake2b_commitment(
		&job, &job.coinbase[0], false, 14, c_local, NULL));
	datum_test(memcmp(c_local, c_pot, sizeof(c_local)) != 0);
	
	// Pooled work can also operate without ABW.
	job.is_datum_job = true;
	datum_test(datum_stratum_job_blake2b_commitment(
		&job, &job.coinbase[0], false, 14, c_local, NULL));
}

static void datum_blake2b_unmasked_block_tests(void) {
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_TEMPLATE_DATA block_template = {0};
	unsigned char hash[32] = {0};
	
	job.block_template = &block_template;
	memset(job.block_target, 0xff, sizeof(job.block_target));
	datum_test(datum_stratum_share_is_unmasked_block(&job, hash));
	job.is_datum_job = true;
	datum_test(datum_stratum_share_is_unmasked_block(&job, hash));
	block_template.abw_enabled = true;
	datum_test(!datum_stratum_share_is_unmasked_block(&job, hash));
}

static void datum_blake2b_h_not_zero_tests(void) {
	T_DATUM_CLIENT_DATA client = {0};
	T_DATUM_MINER_DATA miner = {0};
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_TEMPLATE_DATA tdata = {0};
	T_DATUM_STRATUM_JOB *saved_job = global_cur_stratum_jobs[0];
	char submit[] =
		"{\"id\":7,\"method\":\"mining.submit\",\"params\":["
		"\"miner\",\"0000000000c0de00\",\"0000000000000000\","
		"\"00000000\",\"00000000\"]}";
	static const char expected[] =
		"{\"error\":[23,\"H-not-zero\",null],\"id\":7,\"result\":null}\n";
	
	client.app_client_data = &miner;
	job.block_template = &tdata;
	job.target_pot_index = 0;
	job.coinbase[0].coinb1_len = 1;
	job.coinbase[0].coinb1_bin[0] = 0xff;
	tdata.abw_enabled = true;
	tdata.abw_assignment_id = 1;
	datum_test(datum_blake2b_xor_key_hash(tdata.xor_key_hash,
		(const unsigned char[16]){0}));
	strcpy(job.job_id, "0000000000c0de00");
	miner.stratum_job_diffs[0] = 1;
	global_cur_stratum_jobs[0] = &job;
	
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit) == 0);
	datum_test(miner.share_count_rejected == 1);
	datum_test(client.out_buf == (int)strlen(expected));
	datum_test(!memcmp(client.w_buffer, expected, strlen(expected)));
	
	global_cur_stratum_jobs[0] = saved_job;
}

static void datum_blake2b_coinbase_selection_tests(void) {
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata = calloc(1, sizeof(*sdata));
	T_DATUM_STRATUM_JOB job = {0};
	const bool saved_pooled_only = datum_config.datum_pooled_mining_only;

	datum_test(sdata != NULL);
	if (!sdata) return;

	// Solo / non-pooled behaviour is unchanged.
	datum_config.datum_pooled_mining_only = false;
	datum_test(datum_stratum_coinbase_index(sdata, true) == DATUM_COINBASE_ID_EMPTY);
	datum_test(datum_stratum_coinbase_index(sdata, false) == 0);
	sdata->cur_stratum_job = &job;
	sdata->full_coinbase_ready = true;
	datum_test(datum_stratum_coinbase_index(sdata, false) == 0);
	job.job_state = JOB_STATE_FULL_PRIORITY_WAIT_COINBASER;
	// With the job state at or above JOB_STATE_FULL_PRIORITY_WAIT_COINBASER and
	// full_coinbase_ready set, every miner is served the largest class: there
	// is no per-miner selection on BLAKE2b work.
	datum_test(datum_stratum_coinbase_index(sdata, false) == COINBASE_TYPE_YUGE);
	sdata->full_coinbase_ready = false;
	datum_test(datum_stratum_coinbase_index(sdata, false) == 0);

	// Pooled-only (AlphaPool): the ONLY coinbase a
	// miner may ever receive is the pool's full assigned one. Anything else —
	// the subsidy-only new-block placeholder, the TINY class,
	// a job below the coinbaser-wait state, or no job at all — is NONE, and
	// send_mining_notify sends nothing for NONE.
	datum_config.datum_pooled_mining_only = true;
	datum_test(datum_stratum_coinbase_index(NULL, true) == DATUM_COINBASE_ID_NONE);
	datum_test(datum_stratum_coinbase_index(NULL, false) == DATUM_COINBASE_ID_NONE);
	sdata->full_coinbase_ready = false;
	datum_test(datum_stratum_coinbase_index(sdata, true) == DATUM_COINBASE_ID_NONE);   // new block: no empty work
	datum_test(datum_stratum_coinbase_index(sdata, false) == DATUM_COINBASE_ID_NONE);  // not ready: no TINY
	sdata->full_coinbase_ready = true;
	job.job_state = JOB_STATE_EMPTY_PLUS;
	datum_test(datum_stratum_coinbase_index(sdata, false) == DATUM_COINBASE_ID_NONE);  // below the wait state
	job.job_state = JOB_STATE_FULL_PRIORITY_WAIT_COINBASER;
	datum_test(datum_stratum_coinbase_index(sdata, false) == COINBASE_TYPE_YUGE);      // the one allowed shape
	datum_test(datum_stratum_coinbase_index(sdata, true) == COINBASE_TYPE_YUGE);       // even for "new block" callers
	job.job_state = JOB_STATE_FULL_NORMAL_WAIT_COINBASER;
	datum_test(datum_stratum_coinbase_index(sdata, false) == COINBASE_TYPE_YUGE);
	sdata->cur_stratum_job = NULL;
	datum_test(datum_stratum_coinbase_index(sdata, false) == DATUM_COINBASE_ID_NONE);

	datum_config.datum_pooled_mining_only = saved_pooled_only;
	free(sdata);
}

/* A stand-in stratum server with one active thread, so that
 * datum_stratum_v1_shutdown_all() has someone to ask: every disconnect request
 * ("kick") sets that thread's empty_request flag, which the tests count. */
typedef struct {
	T_DATUM_SOCKET_APP *saved_app;
	T_DATUM_SOCKET_APP app;
	T_DATUM_THREAD_DATA *thread;
} T_R3_KICKS;

static bool r3_kicks_init(T_R3_KICKS *k) {
	memset(k, 0, sizeof(*k));
	k->thread = calloc(1, sizeof(*k->thread)); /* large, but only a few pages are touched */
	if (!k->thread) return false;
	k->thread->is_active = true;
	pthread_mutex_init(&k->thread->thread_data_lock, NULL);
	k->app.max_threads = 1;
	k->app.datum_threads = k->thread;
	k->saved_app = global_stratum_app;
	global_stratum_app = &k->app;
	return true;
}

/* 1 if a disconnect request reached the thread since the last call */
static int r3_kicks_take(T_R3_KICKS *k) {
	const bool kicked = k->thread->empty_request;
	k->thread->empty_request = false;
	return kicked ? 1 : 0;
}

static void r3_kicks_free(T_R3_KICKS *k) {
	global_stratum_app = k->saved_app;
	if (k->thread) pthread_mutex_destroy(&k->thread->thread_data_lock);
	free(k->thread);
}

static void datum_pooled_only_coinbaser_wait_tests(void) {
	// stratum_job_coinbaser_ready(): pooled-only never times out into placeholder
	// work; it keeps waiting and, past the fail-close bound, drops the miners
	// exactly once. Solo keeps the upstream 5 s fallback.
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata = calloc(1, sizeof(*sdata));
	T_DATUM_STRATUM_JOB job = {0};
	const bool saved_pooled_only = datum_config.datum_pooled_mining_only;
	const uint64_t t0 = 5000000; // monotonic ms
	T_R3_KICKS kicks;

	datum_test(sdata != NULL);
	if (!sdata) return;
	if (!datum_test(r3_kicks_init(&kicks))) { free(sdata); return; }
	datum_pooled_outage_reset();
	job.global_index = 0;
	job.need_coinbaser = true;   // the pool's coinbaser has NOT arrived
	job.tsms = 1000000;
	job.job_seq = 1;

	datum_config.datum_pooled_mining_only = true;
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, t0 + 1000) == false);   // 1 s: still waiting
	datum_test(sdata->full_coinbase_ready == false);
	datum_test(datum_pooled_outage_since() == t0 + 1000);                         // the outage starts here
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, t0 + 20000) == false);  // past the old 5 s fallback: STILL waiting
	datum_test(sdata->full_coinbase_ready == false);
	datum_test(r3_kicks_take(&kicks) == 0);
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, t0 + 1000 + DATUM_POOLED_ONLY_COINBASER_FAILCLOSE_MS) == false); // at the bound: not yet
	datum_test(r3_kicks_take(&kicks) == 0);
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, t0 + 1001 + DATUM_POOLED_ONLY_COINBASER_FAILCLOSE_MS) == false); // past it: kick once, keep waiting
	datum_test(r3_kicks_take(&kicks) == 1);
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, t0 + 90000) == false); // idempotent
	datum_test(r3_kicks_take(&kicks) == 0);
	job.need_coinbaser = false;                               // the coinbaser arrives (published)
	datum_pooled_outage_note_published(job.job_seq);
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, t0 + 91000) == true);
	datum_test(sdata->full_coinbase_ready == true);
	datum_test(datum_pooled_outage_since() == 0);

	// Solo: the upstream fallback still fires after 5 s (pool address = the miner's own).
	datum_config.datum_pooled_mining_only = false;
	job.need_coinbaser = true;
	sdata->full_coinbase_ready = false;
	sdata->loop_tsms = job.tsms + 6000;
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, t0 + 100000) == true);
	datum_test(sdata->full_coinbase_ready == false);
	datum_test(datum_pooled_outage_since() == 0);            // solo never touches the tracker
	datum_test(r3_kicks_take(&kicks) == 0);

	datum_pooled_outage_reset();
	r3_kicks_free(&kicks);
	datum_config.datum_pooled_mining_only = saved_pooled_only;
	free(sdata);
}

static void datum_pooled_only_failclose_replacement_tests(void) {
	// AlphaPool release 3: the fail-close must not be restarted
	// by normal template replacement. As a regression test: 240
	// simulated seconds with no usable coinbaser, a new job every 40 s
	// (bitcoind_work_update_seconds' default), the stratum threads asking every
	// second. Measuring each job's own age would never kick (0).
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata = calloc(1, sizeof(*sdata));
	T_DATUM_STRATUM_JOB job = {0};
	const bool saved_pooled_only = datum_config.datum_pooled_mining_only;
	const uint64_t base = 7000000; // monotonic ms
	uint64_t t, first_kick = 0, second_kick = 0;
	int kick_count = 0;
	T_R3_KICKS kicks;

	datum_test(sdata != NULL);
	if (!sdata) return;
	if (!datum_test(r3_kicks_init(&kicks))) { free(sdata); return; }
	datum_config.datum_pooled_mining_only = true;
	datum_pooled_outage_reset();
	for (t = 1; t <= 240000; t += 1000) {
		job.job_seq = 1 + ((t - 1) / 40000);     // a new job per template...
		job.tsms = 1 + ((t - 1) / 40000) * 40000; // ...each "fresh" by its own age
		job.need_coinbaser = true;
		job.global_index = (int)job.job_seq;
		datum_test(stratum_job_coinbaser_ready_at(sdata, &job, base + t) == false);
		if (r3_kicks_take(&kicks)) {
			kick_count++;
			if (!first_kick) first_kick = t;
		}
	}
	datum_test(kick_count == 1);                                 // exactly one, not zero
	datum_test(first_kick > DATUM_POOLED_ONLY_COINBASER_FAILCLOSE_MS);
	datum_test(first_kick <= DATUM_POOLED_ONLY_COINBASER_FAILCLOSE_MS + 2000);
	// new miners are refused from the bound until a coinbaser is published
	datum_test(datum_pooled_only_new_miner_refusal(true, true, base + 240000) == DATUM_POOLED_REFUSE_NO_COINBASER);

	// Positive control: one job, aged past the bound, kicks once.
	datum_pooled_outage_reset();
	job.job_seq = 100; job.need_coinbaser = true; job.global_index = 1;
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, base + 1) == false);
	datum_test(r3_kicks_take(&kicks) == 0);
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, base + 60002) == false);
	datum_test(r3_kicks_take(&kicks) == 1);

	// Only a publication ends the outage: 50 s without one, then one, then a new
	// outage is timed from its own start and kicks 60 s after THAT.
	datum_pooled_outage_reset();
	job.job_seq = 200;
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, base) == false);
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, base + 50000) == false);
	datum_test(r3_kicks_take(&kicks) == 0);
	datum_pooled_outage_note_published(200);
	datum_test(datum_pooled_outage_since() == 0);
	job.job_seq = 201;
	for (t = 51000; t <= 200000; t += 1000) {
		(void)stratum_job_coinbaser_ready_at(sdata, &job, base + t);
		if (r3_kicks_take(&kicks) && !second_kick) second_kick = t;
	}
	datum_test(second_kick == 51000 + DATUM_POOLED_ONLY_COINBASER_FAILCLOSE_MS + 1000);
	// the kick re-arms with a publication: a later outage kicks again
	datum_pooled_outage_note_published(201);
	datum_test(datum_pooled_only_new_miner_refusal(true, true, base + 200001) == DATUM_POOLED_REFUSE_NONE);
	job.job_seq = 202;
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, base + 300000) == false);
	datum_test(stratum_job_coinbaser_ready_at(sdata, &job, base + 360001) == false);
	datum_test(r3_kicks_take(&kicks) == 1);

	// A late look at superseded work cannot start an outage after a publication.
	datum_pooled_outage_reset();
	datum_pooled_outage_note_unready(300, base);
	datum_pooled_outage_note_published(301);
	datum_pooled_outage_note_unready(300, base + 1);   // the older job, seen late
	datum_pooled_outage_note_unready(301, base + 2);   // the published job itself
	datum_test(datum_pooled_outage_since() == 0);
	datum_pooled_outage_note_unready(302, base + 3);   // the next job: a real outage
	datum_test(datum_pooled_outage_since() == base + 3);

	datum_pooled_outage_reset();
	r3_kicks_free(&kicks);
	datum_config.datum_pooled_mining_only = saved_pooled_only;
	free(sdata);
}

/* the coinbaser step's outside world for the outage test: the link is up, and
 * the pool answers with nothing usable */
typedef struct {
	int result;
	uint64_t now;
	int calls;
} T_R3_STRATUM_IO;
static int r3_sio_fetch(void *ctx, T_DATUM_STRATUM_JOB *s, uint64_t *g) {
	T_R3_STRATUM_IO *io = ctx;
	io->calls++;
	*g = 0;
	s->available_coinbase_outputs_count = 0;
	return io->result;
}
static bool r3_sio_link(void *ctx) { (void)ctx; return true; }
static uint64_t r3_sio_generation(void *ctx) { (void)ctx; return 77; }
static uint64_t r3_sio_now(void *ctx) { return ((T_R3_STRATUM_IO *)ctx)->now; }

static void datum_pooled_only_failclose_traffic_tests(void) {
	// Link-up traffic that is not a usable coinbaser — no reply, empty replies,
	// rejected replies, share acknowledgements — never ends the outage: the
	// kick still comes 60 s after it began and new miners are refused.
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata = calloc(1, sizeof(*sdata));
	T_DATUM_STRATUM_JOB *job = calloc(1, sizeof(*job));
	const global_config_t saved_config = datum_config;
	const uint64_t base = 9000000;
	const int results[3] = { DATUM_COINBASER_FETCH_NO_REPLY, 0, DATUM_COINBASER_FETCH_REJECTED };
	unsigned char ack[9] = { DATUM_POW_SHARE_RESPONSE_ACCEPTED };
	T_R3_STRATUM_IO sio = {0};
	const T_DATUM_COINBASER_IO io = { r3_sio_fetch, r3_sio_link, r3_sio_generation, r3_sio_now, &sio };
	uint64_t t, kick_at = 0;
	T_R3_KICKS kicks;
	int k = 0;

	datum_test(sdata != NULL && job != NULL);
	if (!sdata || !job) goto out;
	if (!datum_test(r3_kicks_init(&kicks))) goto out;
	datum_config.datum_pooled_mining_only = true;
	datum_config.override_mining_pool_scriptpubkey_len = 2;
	datum_config.override_mining_pool_scriptpubkey[0] = 0x51;
	datum_config.override_mining_pool_scriptpubkey[1] = 0x51;
	datum_pooled_outage_reset();
	job->need_coinbaser = true;
	job->job_state = JOB_STATE_FULL_PRIORITY_WAIT_COINBASER;
	job->coinbase_value = 312500000;
	job->job_seq = 400;
	job->global_index = 2;
	for (t = 0; t <= 70000; t += 500) {
		sio.now = base + t;
		sio.result = results[(k++) % 3];
		datum_test(datum_coinbaser_job_step(job, &io) != DATUM_COINBASER_STEP_PUBLISHED);
		(void)datum_protocol_share_response(sizeof(ack), ack); // other protocol traffic keeps flowing
		datum_test(datum_pooled_outage_since() == base);
		(void)stratum_job_coinbaser_ready_at(sdata, job, base + t);
		if (r3_kicks_take(&kicks) && !kick_at) kick_at = t;
	}
	datum_test(sio.calls > 100);
	datum_test(job->need_coinbaser == true);
	datum_test(kick_at == DATUM_POOLED_ONLY_COINBASER_FAILCLOSE_MS + 500);
	datum_test(datum_pooled_only_new_miner_refusal(true, true, base + 70000) == DATUM_POOLED_REFUSE_NO_COINBASER);
	r3_kicks_free(&kicks);

out:
	datum_pooled_outage_reset();
	datum_config = saved_config;
	free(job);
	free(sdata);
}

static void datum_pooled_only_listener_rule_tests(void) {
	// The listener's admission rule: upstream refuses pooled-only miners while
	// the link is down; release 3 also refuses them while the pool has sent no
	// usable coinbaser past the fail-close bound, and accepts again on a
	// publication. Not pooled-only: always accepted.
	const uint64_t base = 11000000;
	datum_pooled_outage_reset();
	datum_test(datum_pooled_only_new_miner_refusal(false, false, base) == DATUM_POOLED_REFUSE_NONE);
	datum_test(datum_pooled_only_new_miner_refusal(true, false, base) == DATUM_POOLED_REFUSE_LINK_DOWN);
	datum_test(datum_pooled_only_new_miner_refusal(true, true, base) == DATUM_POOLED_REFUSE_NONE);
	datum_pooled_outage_note_unready(500, base);
	datum_test(datum_pooled_only_new_miner_refusal(true, true, base + DATUM_POOLED_ONLY_COINBASER_FAILCLOSE_MS) == DATUM_POOLED_REFUSE_NONE);
	datum_test(datum_pooled_only_new_miner_refusal(true, true, base + DATUM_POOLED_ONLY_COINBASER_FAILCLOSE_MS + 1) == DATUM_POOLED_REFUSE_NO_COINBASER);
	datum_test(datum_pooled_only_new_miner_refusal(false, true, base + DATUM_POOLED_ONLY_COINBASER_FAILCLOSE_MS + 1) == DATUM_POOLED_REFUSE_NONE);
	datum_test(datum_pooled_only_new_miner_refusal(true, false, base + DATUM_POOLED_ONLY_COINBASER_FAILCLOSE_MS + 1) == DATUM_POOLED_REFUSE_LINK_DOWN);
	datum_pooled_outage_note_published(500);
	datum_test(datum_pooled_only_new_miner_refusal(true, true, base + DATUM_POOLED_ONLY_COINBASER_FAILCLOSE_MS + 2) == DATUM_POOLED_REFUSE_NONE);
	datum_pooled_outage_reset();
}

static void datum_pooled_only_share_class_tests(void) {
	// Pooled-only accepts shares only for what it serves: the validated YUGE
	// class of a published job. A job id naming another class, or the "N"
	// (subsidy-only) form, or a job never published, is unknown work that was
	// not built from the pool's payout assignment.
	T_DATUM_CLIENT_DATA client = {0};
	T_DATUM_MINER_DATA miner = {0};
	T_DATUM_STRATUM_JOB job = {0};
	T_DATUM_TEMPLATE_DATA tdata = {0};
	T_DATUM_STRATUM_JOB *saved_job = global_cur_stratum_jobs[0];
	const bool saved_pooled_only = datum_config.datum_pooled_mining_only;
	char submit_tiny[] = "{\"id\":7,\"method\":\"mining.submit\",\"params\":[\"miner\",\"0000000000c0de00\",\"0000000000000000\",\"00000000\",\"00000000\"]}";
	char submit_yuge[] = "{\"id\":7,\"method\":\"mining.submit\",\"params\":[\"miner\",\"0000000000c0de04\",\"0000000000000000\",\"00000000\",\"00000000\"]}";
	char submit_small[] = "{\"id\":7,\"method\":\"mining.submit\",\"params\":[\"miner\",\"0000000000c0de03\",\"0000000000000000\",\"00000000\",\"00000000\"]}";
	char submit_empty[] = "{\"id\":7,\"method\":\"mining.submit\",\"params\":[\"miner\",\"N0000000000c0deff\",\"0000000000000000\",\"00000000\",\"00000000\"]}";
	static const char unknown[] = "{\"error\":[20,\"unknown-work\",null],\"id\":7,\"result\":null}\n";
	static const char hnotzero[] = "{\"error\":[23,\"H-not-zero\",null],\"id\":7,\"result\":null}\n";
	int i;

	datum_test(!datum_stratum_pooled_share_class_allowed(NULL, false, COINBASE_TYPE_YUGE));
	job.need_coinbaser = false;
	datum_test(datum_stratum_pooled_share_class_allowed(&job, false, COINBASE_TYPE_YUGE));
	datum_test(!datum_stratum_pooled_share_class_allowed(&job, true, COINBASE_TYPE_YUGE));
	for (i = 0; i < MAX_COINBASE_TYPES; i++) {
		if (i != COINBASE_TYPE_YUGE) datum_test(!datum_stratum_pooled_share_class_allowed(&job, false, (unsigned int)i));
	}
	datum_test(!datum_stratum_pooled_share_class_allowed(&job, true, DATUM_COINBASE_ID_EMPTY));
	job.need_coinbaser = true;
	datum_test(!datum_stratum_pooled_share_class_allowed(&job, false, COINBASE_TYPE_YUGE));

	// through the submit path (the H-not-zero fixture: a share that fails the
	// hash check if it gets that far)
	client.app_client_data = &miner;
	job.block_template = &tdata;
	job.target_pot_index = 0;
	job.coinbase[0].coinb1_len = 1;
	job.coinbase[0].coinb1_bin[0] = 0xff;
	job.coinbase[3] = job.coinbase[0];
	job.coinbase[COINBASE_TYPE_YUGE] = job.coinbase[0];
	job.subsidy_only_coinbase = job.coinbase[0];
	tdata.abw_enabled = true;
	tdata.abw_assignment_id = 1;
	datum_test(datum_blake2b_xor_key_hash(tdata.xor_key_hash, (const unsigned char[16]){0}));
	strcpy(job.job_id, "0000000000c0de00");
	miner.stratum_job_diffs[0] = 1;
	global_cur_stratum_jobs[0] = &job;
	job.global_index = 0;
	job.need_coinbaser = false; // published

	datum_config.datum_pooled_mining_only = true;
	client.out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit_tiny) == 0);
	datum_test(client.out_buf == (int)strlen(unknown) && !memcmp(client.w_buffer, unknown, strlen(unknown)));
	client.out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit_small) == 0);
	datum_test(client.out_buf == (int)strlen(unknown) && !memcmp(client.w_buffer, unknown, strlen(unknown)));
	client.out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit_empty) == 0);
	datum_test(client.out_buf == (int)strlen(unknown) && !memcmp(client.w_buffer, unknown, strlen(unknown)));
	client.out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit_yuge) == 0);      // passes the class check
	datum_test(client.out_buf == (int)strlen(hnotzero) && !memcmp(client.w_buffer, hnotzero, strlen(hnotzero)));
	job.need_coinbaser = true;                                                            // never published
	client.out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit_yuge) == 0);
	datum_test(client.out_buf == (int)strlen(unknown) && !memcmp(client.w_buffer, unknown, strlen(unknown)));

	// not pooled-only: unchanged, any class reaches the hash check
	datum_config.datum_pooled_mining_only = false;
	client.out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, submit_tiny) == 0);
	datum_test(client.out_buf == (int)strlen(hnotzero) && !memcmp(client.w_buffer, hnotzero, strlen(hnotzero)));

	datum_config.datum_pooled_mining_only = saved_pooled_only;
	global_cur_stratum_jobs[0] = saved_job;
}

static void datum_pooled_only_local_coinbase_tests(void) {
	// The coinbaser thread's fallback rule: with the pool link down, solo may
	// build a local coinbase (it pays the miner's own address); pooled-only
	// never may (zero pool outputs = no payout assignment to build from).
	// With the link up nobody builds locally — the pool's coinbaser is used.
	datum_test(datum_coinbaser_local_fallback_allowed(false, false) == true);
	datum_test(datum_coinbaser_local_fallback_allowed(false, true) == false);
	datum_test(datum_coinbaser_local_fallback_allowed(true, false) == false);
	datum_test(datum_coinbaser_local_fallback_allowed(true, true) == false);
}

static void datum_pooled_only_outputs_decision_tests(void) {
	// What the coinbaser thread may build from a fetch result:
	// pooled-only builds ONLY from a reply that carries payout outputs; a reply
	// with none, a timeout/error (-1) or a dead link (-1) keeps the job waiting.
	// Solo keeps upstream's behaviour and mines on its own address in all of those.
	datum_test(datum_coinbaser_outputs_decision(74, true) == 74);
	datum_test(datum_coinbaser_outputs_decision(1, true) == 1);
	datum_test(datum_coinbaser_outputs_decision(0, true) == -1);
	datum_test(datum_coinbaser_outputs_decision(-1, true) == -1);
	datum_test(datum_coinbaser_outputs_decision(74, false) == 74);
	datum_test(datum_coinbaser_outputs_decision(0, false) == 0);
	datum_test(datum_coinbaser_outputs_decision(-1, false) == 0);
}

static void datum_stratum_abw_block_request_tests(void) {
	unsigned char xor_key[16];
	unsigned char raw_hash[32], masked_hash[32];
	for (size_t i = 0; i < sizeof(xor_key); ++i) {
		xor_key[i] = (unsigned char)(i + 1);
	}
	for (size_t i = 0; i < sizeof(raw_hash); ++i) {
		raw_hash[i] = (unsigned char)(0x80 + i);
	}
	datum_test(datum_blake2b_apply_xor_mask_le(
		masked_hash, raw_hash, xor_key, 42));
	
	unsigned char header[DATUM_BLAKE2B_BLOCK_HEADER_SIZE] = {0};
	const unsigned char coinbase[] = {1, 0, 0, 0, 0, 0, 0, 0};
	const char transactions_hex[] = "0102";
	char request[2048], original[2048], block_hash[65];
	size_t header_offset = 0;
	header[DATUM_BLAKE2B_HEADER_XOR_CLEAR_BITS_OFFSET] = 42;
	const size_t request_size = datum_stratum_build_block_request_parts(
		request, sizeof(request), header, coinbase, sizeof(coinbase), false,
		1, transactions_hex, sizeof(transactions_hex) - 1, false,
		&header_offset);
	datum_test(request_size > 0);
	datum_test(strstr(request, "0102\"]}") != NULL);
	memcpy(original, request, request_size + 1);
	unsigned char wrong_hash[32];
	memcpy(wrong_hash, masked_hash, sizeof(wrong_hash));
	wrong_hash[0] ^= 1;
	datum_test(!datum_stratum_abw_finalize_block_request(request,
		request_size, header_offset, raw_hash, 42, xor_key,
		wrong_hash, block_hash));
	datum_test(!memcmp(request, original, request_size + 1));
	datum_test(datum_stratum_abw_finalize_block_request(request,
		request_size, header_offset, raw_hash, 42, xor_key,
		masked_hash, block_hash));
	datum_test(!memcmp(request + header_offset +
		DATUM_BLAKE2B_HEADER_XOR_KEY_OFFSET * 2, "01020304", 8));
	for (size_t i = 0; i < sizeof(masked_hash); ++i) {
		datum_test(hex2bin_uchar(block_hash + i * 2) == masked_hash[31 - i]);
	}
}

static void datum_block_coinbase_witness_tests(void) {
	static const unsigned char stripped[] = {
		0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
	};
	static const unsigned char witnessed[] = {
		0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
	};
	static const char zero_witness[] =
		"01200000000000000000000000000000000000000000000000000000000000000000";
	char output[256] = {0};
	T_DATUM_TEMPLATE_DATA tdata = {0};
	T_DATUM_STRATUM_JOB job = {.block_template = &tdata};
	size_t size;
	
	datum_test(!datum_stratum_block_needs_witness(&job, false));
	tdata.default_witness_commitment[0] = '1';
	datum_test(datum_stratum_block_needs_witness(&job, false));
	datum_test(!datum_stratum_block_needs_witness(&job, true));
	datum_test(!datum_stratum_block_needs_witness(NULL, false));
	
	size = datum_stratum_coinbase_for_block_hex(
		output, sizeof(output), stripped, sizeof(stripped), true);
	output[size] = 0;
	datum_test(size == (sizeof(stripped) + 36) * 2);
	datum_test(!strncmp(output, "0100000000010102", 16));
	datum_test(!strncmp(output + 16, zero_witness, sizeof(zero_witness) - 1));
	datum_test(!strcmp(output + 16 + sizeof(zero_witness) - 1, "00000000"));
	
	memset(output, 0, sizeof(output));
	size = datum_stratum_coinbase_for_block_hex(
		output, sizeof(output), witnessed, sizeof(witnessed), true);
	datum_test(size == sizeof(witnessed) * 2);
	datum_test(!strncmp(output, "010000000001010200000000", size));
	
	memset(output, 0, sizeof(output));
	size = datum_stratum_coinbase_for_block_hex(
		output, sizeof(output), stripped, sizeof(stripped), false);
	datum_test(size == sizeof(stripped) * 2);
	datum_test(!strncmp(output, "01000000010200000000", size));
	datum_test(!datum_stratum_coinbase_for_block_hex(
		output, (sizeof(stripped) + 36) * 2 - 1, stripped, sizeof(stripped), true));
	datum_test(!datum_stratum_coinbase_for_block_hex(
		output, sizeof(output), stripped, 7, true));
}

static void datum_stratum_string_request_id_tests(void) {
	T_DATUM_CLIENT_DATA client = {0};
	T_DATUM_MINER_DATA miner = {0};
	char authorize[] =
		"{\"id\":\"authorize-17\",\"method\":\"mining.authorize\","
		"\"params\":[\"hardware.worker\",\"password\"]}";
	char authorize_numeric[] =
		"{\"id\":18,\"method\":\"mining.authorize\","
		"\"params\":[\"hardware.worker\",\"password\"]}";
	char unknown[] =
		"{\"id\":\"unknown-19\",\"method\":\"mining.unknown\",\"params\":[]}";
	char oversized[512];
	
	client.app_client_data = &miner;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, authorize) == 0);
	datum_test(miner.authorized);
	datum_test(!strcmp(miner.last_auth_username, "hardware.worker"));
	datum_test(client.out_buf == (int)strlen("{\"error\":null,\"id\":\"authorize-17\",\"result\":true}\n"));
	datum_test(!memcmp(client.w_buffer,
		"{\"error\":null,\"id\":\"authorize-17\",\"result\":true}\n", client.out_buf));
	datum_test(miner.request_id_json[0] == 0);
	client.out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, authorize_numeric) == 0);
	datum_test(client.out_buf == (int)strlen("{\"error\":null,\"id\":18,\"result\":true}\n"));
	datum_test(!memcmp(client.w_buffer,
		"{\"error\":null,\"id\":18,\"result\":true}\n", client.out_buf));
	client.out_buf = 0;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, unknown) == 0);
	datum_test(client.out_buf == (int)strlen(
		"{\"error\":[-3,\"Method not found\",null],\"id\":\"unknown-19\",\"result\":null}\n"));
	datum_test(!memcmp(client.w_buffer,
		"{\"error\":[-3,\"Method not found\",null],\"id\":\"unknown-19\",\"result\":null}\n",
		client.out_buf));
	datum_test(miner.request_id_json[0] == 0);
	snprintf(oversized, sizeof(oversized),
		"{\"id\":\"%0130d\",\"method\":\"mining.authorize\",\"params\":[]}", 0);
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, oversized) == -4);
}

static void datum_stratum_minimum_difficulty_configure_tests(void) {
	T_DATUM_CLIENT_DATA client = {0};
	T_DATUM_MINER_DATA miner = {0};
	char configure[] =
		"{\"id\":20,\"method\":\"mining.configure\","
		"\"params\":[[\"minimum-difficulty\"],{}]}";
	static const char expected[] =
		"{\"error\":null,\"id\":20,\"result\":{\"minimum-difficulty\":false}}\n";
	
	client.app_client_data = &miner;
	datum_test(datum_stratum_v1_socket_thread_client_cmd(&client, configure) == 0);
	datum_test(client.out_buf == (int)strlen(expected));
	datum_test(!memcmp(client.w_buffer, expected, strlen(expected)));
}


void datum_stratum_mod_username_tests() {
	const char * const s_umods = "{\"x\":{\"addrA\": 0.3}, \"abc\":{\"addrB\":0.3,\"addrC\":0.3},\":)\":{\"\":0.5},\"a.c\":{\"addrD\":1.0}}";
	json_error_t err;
	json_t * const j_umods = JSON_LOADS(s_umods, &err);
	assert(j_umods);
	struct datum_username_mod *umods = NULL;
	int ret = datum_config_parse_username_mods(&umods, j_umods, false);
	assert(ret == 1);
	json_decref(j_umods);
	datum_config.stratum_username_mod = umods;
	
	char buf[0x100];
	char * const pool_addr = datum_config.mining_pool_address;
	char *s, *modname;
	const char *res, *a1, *a2;
	
	strcpy(pool_addr, "dummy");
	
	s = "def~G";
	modname = &s[4];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 1) == s);
	
	s = "def~x";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 1) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 1) == pool_addr);
	
	s = "def~abc";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3);
	if (0 == strcmp(res, "addrB")) {  // jansson doesn't order keys'
		a1 = "addrB";
		a2 = "addrC";
	} else {
		a1 = "addrC";
		a2 = "addrB";
	}
	datum_test(0 == strcmp(res, a1));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 3);
	datum_test(0 == strcmp(res, a1));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 3);
	datum_test(0 == strcmp(res, a2));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x9999, modname, 3);
	datum_test(0 == strcmp(res, a2));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x999a, modname, 3) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 3) == pool_addr);
	
	s = "def.ghi~abc";
	modname = &s[8];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a1, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a1, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a2, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x9999, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a2, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x999a, modname, 3) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 3) == pool_addr);
	
	s = "def.ghi~:)";
	modname = &s[8];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 2) == buf);
	datum_test(0 == strcmp(buf, "def.ghi"));
	memset(buf, 0, 7);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x7fff, modname, 2) == buf);
	datum_test(0 == strcmp(buf, "def.ghi"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x8000, modname, 2) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 2) == pool_addr);
	
	s = "xyz~a.c";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3);
	datum_test(0 == strcmp(res, "addrD"));
	
	// Intentionally overflow buf with address: we lose the worker name, but get the full address via its umod buffer
	s = "def.ghi~x";
	modname = &s[8];
	memset(buf, 0x0e, 8);
	res = datum_stratum_mod_username(s, buf, 2, 0, modname, 1);
	datum_test(res != buf);
	datum_test(res != pool_addr);
	datum_test(buf[2] == 0x0e);
	datum_test(0 == strcmp(res, "addrA"));
	res = datum_stratum_mod_username(s, buf, 2, 0x4ccc, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	datum_test(datum_stratum_mod_username(s, buf, 2, 0x4ccd, modname, 1) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, 2, 0xffff, modname, 1) == pool_addr);
	datum_test(buf[2] == 0x0e);
	datum_test(buf[6] == 0x0e);
	res = datum_stratum_mod_username(s, buf, 6, 0, modname, 1);
	datum_test(res == buf);
	datum_test(res != pool_addr);
	datum_test(buf[6] == 0x0e);
	datum_test(0 == strcmp(res, "addrA"));
	memset(buf, 0x0e, 9);
	datum_test(datum_stratum_mod_username(s, buf, 7, 0, modname, 1) == buf);
	datum_test(buf[8] == 0x0e);
	datum_test(0 == strcmp(res, "addrA."));
	memset(buf, 0x0e, 10);
	datum_test(datum_stratum_mod_username(s, buf, 8, 0, modname, 1) == buf);
	datum_test(buf[9] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.g"));
	memset(buf, 0x0e, 11);
	datum_test(datum_stratum_mod_username(s, buf, 9, 0, modname, 1) == buf);
	datum_test(buf[10] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.gh"));
	memset(buf, 0x0e, 12);
	datum_test(datum_stratum_mod_username(s, buf, 10, 0, modname, 1) == buf);
	datum_test(buf[11] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.ghi"));
	s = "def.ghi~:)";
	modname = &s[8];
	memset(buf, 0x0e, 9);
	datum_test(datum_stratum_mod_username(s, buf, 2, 0, modname, 2) == buf);
	datum_test(buf[2] == 0x0e);
	datum_test(0 == strcmp(res, "d"));
	datum_test(datum_stratum_mod_username(s, buf, 6, 0, modname, 2) == buf);
	datum_test(buf[6] == 0x0e);
	datum_test(0 == strcmp(res, "def.g"));
	datum_test(datum_stratum_mod_username(s, buf, 7, 0, modname, 2) == buf);
	datum_test(buf[7] == 0x0e);
	datum_test(0 == strcmp(res, "def.gh"));
	datum_test(datum_stratum_mod_username(s, buf, 8, 0, modname, 2) == buf);
	datum_test(buf[8] == 0x0e);
	datum_test(0 == strcmp(res, "def.ghi"));
}

void datum_stratum_tests(void) {
	datum_stratum_mod_username_tests();
	datum_stratum_minimum_difficulty_configure_tests();
	datum_stratum_string_request_id_tests();
	datum_blake2b_coinbase_selection_tests();
	datum_pooled_only_coinbaser_wait_tests();
	datum_pooled_only_failclose_replacement_tests();
	datum_pooled_only_failclose_traffic_tests();
	datum_pooled_only_listener_rule_tests();
	datum_pooled_only_share_class_tests();
	datum_pooled_only_local_coinbase_tests();
	datum_pooled_only_outputs_decision_tests();
	datum_blake2b_h_not_zero_tests();
	datum_blake2b_client_pot_commitment_tests();
	datum_blake2b_unmasked_block_tests();
	datum_stratum_abw_block_request_tests();
	datum_blake2b_refresh_time_offset_tests();
	datum_block_coinbase_witness_tests();
}
