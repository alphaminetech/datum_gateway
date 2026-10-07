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
 * Copyright (c) 2024-2026 Bitcoin Ocean, LLC, Jason Hughes, and individual contributors
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

#ifndef _DATUM_COINBASE_H_
#define _DATUM_COINBASE_H_

#include <stdbool.h>
#include <stdint.h>

#include "datum_blocktemplates.h"

#define MAX_COINBASE_TAG_SPACE 82 // leaves space for BIP34 height, extranonces, datum prime tag, etc.

// The most payout outputs one pool coinbaser may carry (the job's
// available_coinbase_outputs[] array). A reply with more is rejected whole.
#define DATUM_COINBASER_MAX_OUTPUTS 512

typedef struct T_DATUM_STRATUM_JOB T_DATUM_STRATUM_JOB;

// Pooled-only (AlphaPool release 3): what a fetched assignment is bound to,
// frozen when it was requested. The coinbase built from the assignment uses
// exactly this and nothing live: the DATUM session the request went out on,
// and the pool's remainder script (the 0x99 override script) at that time.
typedef struct {
	uint64_t session_generation;
	unsigned char pool_script[MAX_OUTPUT_SCRIPT_LEN];
	int pool_script_len;
} T_DATUM_POOLED_SETTLEMENT;

// datum_coinbaser_pooled_coinbase_check() results
#define DATUM_CB_CHECK_OK 0
#define DATUM_CB_CHECK_NO_ASSIGNMENT 1      // the job holds no assignment, or no pool script to check against
#define DATUM_CB_CHECK_MALFORMED 2          // the served coinbase does not decode as exactly one transaction
#define DATUM_CB_CHECK_MISSING_OUTPUT 3     // an assignment output (script + value) is not in it (e.g. truncated)
#define DATUM_CB_CHECK_EXTRA_OUTPUT 4       // an output that is none of: assignment, pool remainder, zero-value OP_RETURN
#define DATUM_CB_CHECK_NONZERO_OP_RETURN 5  // an OP_RETURN output (commitment, extranonce, dead output) carries value
#define DATUM_CB_CHECK_POOL_AMOUNT 6        // the pool output is missing, repeated, or not exactly the remainder
#define DATUM_CB_CHECK_TOTAL 7              // the outputs do not add up to exactly the job's coinbase value

// The coinbaser thread's per-job step, with its outside world injected so tests
// can drive it without sockets. fetch() is datum_protocol_coinbaser_fetch_ex():
// >0 payout outputs parsed into the job, 0 a reply that carried none, -1 no
// usable reply; on >0 it sets *request_generation to the session the request
// was sent on. now_ms() is monotonic milliseconds.
typedef struct {
	int (*fetch)(void *ctx, T_DATUM_STRATUM_JOB *s, uint64_t *request_generation);
	bool (*link_active)(void *ctx);
	uint64_t (*session_generation)(void *ctx);
	uint64_t (*now_ms)(void *ctx);
	void *ctx;
} T_DATUM_COINBASER_IO;

#define DATUM_COINBASER_STEP_WAIT 0        // nothing published; the job keeps waiting, ask again
#define DATUM_COINBASER_STEP_PUBLISHED 1   // coinbase built (and in pooled-only mode validated) and need_coinbaser cleared
#define DATUM_COINBASER_STEP_BACKOFF 2     // a reply came back but was not usable: wait a little before asking again

int datum_coinbaser_init(void);
int generate_coinbase_input(int height, char *cb, int *target_pot_index);
void generate_coinbase_txns_for_stratum_job_subtypebysize(T_DATUM_STRATUM_JOB *s, int coinbase_index, int remaining_size, bool space_for_en_in_coinbase, int *cb1idx, int *cb2idx, bool special_coinb1);
void generate_coinbase_txns_for_stratum_job(T_DATUM_STRATUM_JOB *s, bool empty_only);
bool generate_coinbase_txns_for_stratum_job_pooled(T_DATUM_STRATUM_JOB *s, const T_DATUM_POOLED_SETTLEMENT *settle);
void generate_base_coinbase_txns_for_stratum_job(T_DATUM_STRATUM_JOB *s, bool new_block);
int datum_coinbaser_v2_parse(T_DATUM_STRATUM_JOB *s, unsigned char *coinbaser, int cblen, bool must_free);
int datum_coinbaser_pooled_coinbase_check(const T_DATUM_STRATUM_JOB *s, int coinbase_index, const T_DATUM_POOLED_SETTLEMENT *settle);
const char *datum_coinbaser_check_reason(int code);
int datum_coinbaser_job_step(T_DATUM_STRATUM_JOB *s, const T_DATUM_COINBASER_IO *io);

#endif
