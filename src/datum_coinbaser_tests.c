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
 * Copyright (c) 2026 Justin Filip and individual contributors
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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "datum_conf.h"
#include "datum_stratum.h"
#include "datum_coinbaser.h"
#include "datum_protocol.h"
#include "datum_protocol_internal.h"
#include "datum_utils.h"
#include "datum_pow.h"

int datum_stratum_coinbase_fit_to_template(
	int max_sz, int fixed_bytes, T_DATUM_STRATUM_JOB *s);

static void datum_prime_id_64bit_tests(void) {
	const uint64_t saved_prime_id = datum_config.prime_id;
	const uint16_t saved_unique_id = datum_config.coinbase_unique_id;
	char coinbase_input[1024] = {0};
	int target_pot_index = -1;
	
	datum_config.prime_id = UINT64_C(0x887766555d965e4e);
	datum_config.coinbase_unique_id = 0x1234;
	const int coinbase_input_size = generate_coinbase_input(
		42, coinbase_input, &target_pot_index);
	datum_test(coinbase_input_size >= target_pot_index + 11);
	datum_test(!strncmp(
		coinbase_input + (target_pot_index - 1) * 2,
		"0bff34124e5e965d55667788", 24));

	// a pool id that fits in 32 bits: the classic 7-byte push, as other DATUM gateway builds write it
	// (07, PoT byte, unique id 9210, pool id 0150de71 — on chain the PoT byte is the live target, here the placeholder)
	datum_config.prime_id = UINT64_C(0x71DE5001);
	datum_config.coinbase_unique_id = 0x1092;
	memset(coinbase_input, 0, sizeof(coinbase_input));
	target_pot_index = -1;
	const int size32 = generate_coinbase_input(42, coinbase_input, &target_pot_index);
	datum_test(size32 == target_pot_index + 7);
	datum_test(!strncmp(coinbase_input + (target_pot_index - 1) * 2, "07ff92100150de71", 16));
	datum_test(size32 == coinbase_input_size - 4);

	datum_config.prime_id = saved_prime_id;
	datum_config.coinbase_unique_id = saved_unique_id;
}

static void datum_blake2b_coinbase_limit_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB job;
	
	memset(&tdata, 0, sizeof(tdata));
	memset(&job, 0, sizeof(job));
	job.block_template = &tdata;
	tdata.sizelimit = 85 + 36 + 950;
	tdata.weightlimit = 4000000;
	
	/* The 164-byte header shrinks the coinbase leftover by 84 bytes. */
	datum_test(datum_stratum_coinbase_fit_to_template(1000, 0, &job) == 866);
	
	/* The weight limit: the header and a five-byte count at four units a byte,
	 * the coinbase's 36 witness bytes, then 950 bytes of coinbase at four
	 * each. With the 80-byte header's 340 the leftover was 1000 (unbound). */
	tdata.sizelimit = 4000000;
	tdata.weightlimit = ((DATUM_BLAKE2B_BLOCK_HEADER_SIZE + 5) * 4) + 36 + (4 * 950);
	datum_test(datum_stratum_coinbase_fit_to_template(1000, 0, &job) == 950);
	/* The transactions' weight counts the same way. */
	tdata.txn_total_weight = 4000;
	tdata.weightlimit += 4000;
	datum_test(datum_stratum_coinbase_fit_to_template(1000, 0, &job) == 950);
	/* Fixed bytes are subtracted from the leftover. */
	datum_test(datum_stratum_coinbase_fit_to_template(1000, 100, &job) == 850);
}

/* P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG, 25 bytes. */
static const unsigned char datum_test_p2pkh_script[25] = {0x76, 0xa9, 0x14, [23] = 0x88, 0xac};
/* P2WPKH: OP_0 <20 bytes>, 22 bytes. */
static const unsigned char datum_test_p2wpkh_script[22] = {0x00, 0x14};

/* Builds one coinbase class with the template's used sigop cost set to
 * sigops_used and the pool script set to P2PKH or P2WPKH, and returns the hex
 * output count that follows the 8-character sequence at the start of coinb2.
 * The count covers the included outputs plus the pool output and the witness
 * commitment. The job's candidate outputs are two P2PKH outputs (cost 4 each)
 * and one P2WPKH output (cost 0). */
static const char *datum_coinbase_output_count_hex(T_DATUM_STRATUM_JOB *job, uint32_t sigops_used, bool pool_p2pkh) {
	int cb1idx[MAX_COINBASE_TYPES] = {0};
	int cb2idx[MAX_COINBASE_TYPES] = {0};
	
	job->block_template->txn_total_sigops = sigops_used;
	if (pool_p2pkh) {
		memcpy(job->pool_addr_script, datum_test_p2pkh_script, sizeof(datum_test_p2pkh_script));
		job->pool_addr_script_len = sizeof(datum_test_p2pkh_script);
	} else {
		memcpy(job->pool_addr_script, datum_test_p2wpkh_script, sizeof(datum_test_p2wpkh_script));
		job->pool_addr_script_len = sizeof(datum_test_p2wpkh_script);
	}
	memset(job->coinbase[1].coinb2, 0, sizeof(job->coinbase[1].coinb2));
	generate_coinbase_txns_for_stratum_job_subtypebysize(job, 1, 1000, true, cb1idx, cb2idx, false);
	return job->coinbase[1].coinb2 + 8;
}

static void datum_blake2b_coinbase_sigops_tests(void) {
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_STRATUM_JOB *job = calloc(1, sizeof(*job));
	int k;
	
	datum_test(job != NULL);
	if (!job) return;
	memset(&tdata, 0, sizeof(tdata));
	tdata.sigoplimit = 80000;
	job->block_template = &tdata;
	job->coinbase_value = 5000000000ULL;
	for (k = 0; k < 3; k++) {
		job->available_coinbase_outputs[k].value_sats = 100000000;
		if (k < 2) {
			memcpy(job->available_coinbase_outputs[k].output_script, datum_test_p2pkh_script, sizeof(datum_test_p2pkh_script));
			job->available_coinbase_outputs[k].output_script_len = sizeof(datum_test_p2pkh_script);
			job->available_coinbase_outputs[k].sigops = 4;
		} else {
			memcpy(job->available_coinbase_outputs[k].output_script, datum_test_p2wpkh_script, sizeof(datum_test_p2wpkh_script));
			job->available_coinbase_outputs[k].output_script_len = sizeof(datum_test_p2wpkh_script);
			job->available_coinbase_outputs[k].sigops = 0;
		}
	}
	job->available_coinbase_outputs_count = 3;
	
	/* Space for every output: all three, the pool output and the witness commitment. */
	datum_test(!strncmp(datum_coinbase_output_count_hex(job, 0, false), "05", 2));
	/* Budget for one P2PKH output: the first P2PKH is included, the second is
	 * skipped, and the P2WPKH is included. */
	datum_test(!strncmp(datum_coinbase_output_count_hex(job, 80000 - 4, false), "04", 2));
	/* Budget of 0: only the P2WPKH output is included. */
	datum_test(!strncmp(datum_coinbase_output_count_hex(job, 80000, false), "03", 2));
	/* A P2PKH pool output takes the remaining 4 units of the budget, so neither
	 * P2PKH candidate is included. */
	datum_test(!strncmp(datum_coinbase_output_count_hex(job, 80000 - 4, true), "03", 2));
	free(job);
}

/* ------------------------------------------------------------------------
 * AlphaPool release 3 — pooled-only coinbase safety.
 * The fixtures build jobs the way the gateway
 * does (real parser, real builder) against a template with a witness
 * commitment, with a pool fee script as the 0x99 pool script and an
 * assignment that covers every satoshi of the coinbase value, the pool's
 * own line included.
 * ------------------------------------------------------------------------ */

/* The pool's own (fee) script: P2PKH, 25 bytes. Also the 0x99 override (pool) script. */
static const unsigned char r3_ops_script[25] = {
	0x76, 0xa9, 0x14,
	0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0x01, 0x02, 0x03, 0x04,
	0x88, 0xac,
};
/* The operator's local mining.pool_address (BIP173 test vector, P2WPKH) and its script. */
static const char r3_local_pool_address[] = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
static const unsigned char r3_local_pool_script[22] = {
	0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
	0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
};
#define R3_VALUE UINT64_C(312537913) /* subsidy + fees, as a template states it */

static void r3_miner_script(unsigned char *script, int k) {
	int i;
	script[0] = 0x00; /* P2WPKH: OP_0 PUSH20 <20 bytes>, distinct per miner */
	script[1] = 0x14;
	for (i = 0; i < 20; i++) script[2 + i] = (unsigned char)(k * 7 + i + 1);
}

/* A 0x11 coinbaser payload (what follows value and length): the coinbaser ID,
 * n_miners P2WPKH lines sharing 97% of value, then (with_ops) the pool's own line with
 * the remainder. With with_ops the lines add up to exactly value. */
static int r3_assignment_blob(unsigned char *blob, uint64_t value, int n_miners, bool with_ops, uint8_t cbid) {
	const uint64_t miner_total = (value / 100) * 97;
	const uint64_t each = n_miners ? (miner_total / (uint64_t)n_miners) : 0;
	int i = 0, k;

	blob[i++] = cbid;
	for (k = 0; k < n_miners; k++) {
		pk_u64le(blob, i, each); i += 8;
		blob[i++] = 22;
		r3_miner_script(&blob[i], k); i += 22;
	}
	if (with_ops) {
		pk_u64le(blob, i, value - (each * (uint64_t)n_miners)); i += 8;
		blob[i++] = sizeof(r3_ops_script);
		memcpy(&blob[i], r3_ops_script, sizeof(r3_ops_script)); i += sizeof(r3_ops_script);
	}
	return i;
}

static void r3_template_init(T_DATUM_TEMPLATE_DATA *tdata, uint64_t value) {
	memset(tdata, 0, sizeof(*tdata));
	tdata->sizelimit = 4000000;
	tdata->weightlimit = 4000000;
	tdata->sigoplimit = 80000;
	tdata->height = 1000000;
	tdata->coinbasevalue = value;
	tdata->curtime = 1758600000;
	tdata->version = 0x20000000;
	tdata->bits_uint = 0x1d00ffff;
	strcpy(tdata->default_witness_commitment,
		"6a24aa21a9ed1111111111111111111111111111111111111111111111111111111111111111");
}

static T_DATUM_STRATUM_JOB *r3_job_new(T_DATUM_TEMPLATE_DATA *tdata, int global_index, uint64_t job_seq) {
	T_DATUM_STRATUM_JOB *job = calloc(1, sizeof(*job));
	if (!job) return NULL;
	job->block_template = tdata;
	job->coinbase_value = tdata->coinbasevalue;
	job->height = tdata->height;
	job->enprefix = 0x1a2b;
	job->job_state = JOB_STATE_FULL_PRIORITY_WAIT_COINBASER;
	job->need_coinbaser = true;
	job->global_index = global_index;
	job->job_seq = job_seq;
	return job;
}

/* pooled-only fixture: a 0x99 pool script, coinbase tags and ids */
static void r3_config_pooled(void) {
	datum_config.datum_pooled_mining_only = true;
	memcpy(datum_config.override_mining_pool_scriptpubkey, r3_ops_script, sizeof(r3_ops_script));
	datum_config.override_mining_pool_scriptpubkey_len = sizeof(r3_ops_script);
	strcpy(datum_config.override_mining_coinbase_tag_primary, "AlphaPool");
	strcpy(datum_config.mining_coinbase_tag_primary, "local");
	strcpy(datum_config.mining_coinbase_tag_secondary, "Gateway Tag 01");
	strcpy(datum_config.mining_pool_address, r3_local_pool_address);
	datum_config.prime_id = UINT64_C(0x887766555d965e4e);
	datum_config.coinbase_unique_id = 0x1234;
	datum_config.override_vardiff_min = 0;
}

static void r3_settlement(T_DATUM_POOLED_SETTLEMENT *settle, uint64_t generation) {
	memset(settle, 0, sizeof(*settle));
	settle->session_generation = generation;
	memcpy(settle->pool_script, r3_ops_script, sizeof(r3_ops_script));
	settle->pool_script_len = sizeof(r3_ops_script);
}

static void r3_rwlocks_init(void) {
	int i;
	for (i = 0; i < MAX_STRATUM_JOBS; i++) pthread_rwlock_init(&need_coinbaser_rwlocks[i], NULL);
	need_coinbaser_rwlocks_init_done = true;
}

/* An independent decoder for the tests' own assertions (not the validator's). */
typedef struct {
	uint64_t value;
	unsigned char script[128];
	int len;
	size_t value_off; /* offset of the value in the assembled transaction */
} T_R3_OUT;

static void r3_assemble(const T_DATUM_STRATUM_JOB *job, int cls, unsigned char *tx, size_t *len) {
	const T_DATUM_STRATUM_COINBASE *cb = &job->coinbase[cls];
	memcpy(tx, cb->coinb1_bin, cb->coinb1_len);
	memset(tx + cb->coinb1_len, 0, 12);
	memcpy(tx + cb->coinb1_len + 12, cb->coinb2_bin, cb->coinb2_len);
	*len = (size_t)cb->coinb1_len + 12 + (size_t)cb->coinb2_len;
}

static uint64_t r3_varint(const unsigned char *tx, size_t *p) {
	const unsigned char b = tx[(*p)++];
	uint64_t v = 0;
	int n, i;
	if (b < 0xfd) return b;
	n = (b == 0xfd) ? 2 : ((b == 0xfe) ? 4 : 8);
	for (i = 0; i < n; i++) v |= ((uint64_t)tx[*p + i]) << (8 * i);
	*p += n;
	return v;
}

static int r3_decode(const T_DATUM_STRATUM_JOB *job, int cls, T_R3_OUT *outs, int max) {
	unsigned char tx[MAX_COINBASE_TXN_SIZE_BYTES];
	size_t len, p = 4;
	uint64_t n, k, sl;

	if (job->coinbase[cls].coinb1_len < 1) return -1;
	r3_assemble(job, cls, tx, &len);
	if (r3_varint(tx, &p) != 1) return -1;
	p += 36;
	sl = r3_varint(tx, &p);
	p += sl + 4;
	n = r3_varint(tx, &p);
	if ((int)n > max) return -1;
	for (k = 0; k < n; k++) {
		if (p + 9 > len) return -1;
		outs[k].value_off = p;
		outs[k].value = upk_u64le(tx, (int)p); p += 8;
		sl = r3_varint(tx, &p);
		if ((sl > sizeof(outs[k].script)) || (p + sl > len)) return -1;
		memcpy(outs[k].script, tx + p, sl);
		outs[k].len = (int)sl;
		p += sl;
	}
	if (p + 4 != len) return -1;
	return (int)n;
}

/* Overwrite bytes of the assembled transaction in the job's class cls (they
 * live in coinb1_bin or coinb2_bin; the 12 extranonce bytes are not touched). */
static void r3_patch(T_DATUM_STRATUM_JOB *job, int cls, size_t tx_off, const unsigned char *bytes, size_t n) {
	T_DATUM_STRATUM_COINBASE *cb = &job->coinbase[cls];
	size_t i, o;
	for (i = 0; i < n; i++) {
		o = tx_off + i;
		if (o < (size_t)cb->coinb1_len) cb->coinb1_bin[o] = bytes[i];
		else if (o >= (size_t)cb->coinb1_len + 12) cb->coinb2_bin[o - cb->coinb1_len - 12] = bytes[i];
	}
}

static void r3_patch_value(T_DATUM_STRATUM_JOB *job, int cls, size_t tx_off, uint64_t value) {
	unsigned char b[8];
	pk_u64le(b, 0, value);
	r3_patch(job, cls, tx_off, b, 8);
}

/* index of the first decoded output with this script, or -1 */
static int r3_find(const T_R3_OUT *outs, int n, const unsigned char *script, int len) {
	int k;
	for (k = 0; k < n; k++) {
		if ((outs[k].len == len) && !memcmp(outs[k].script, script, len)) return k;
	}
	return -1;
}

/* ---- the parser rejects a bad reply whole and leaves the job as it was ---- */

static int r3_blob_outputs(unsigned char *blob, uint8_t cbid, const uint64_t *values, int n) {
	int i = 0, k;
	blob[i++] = cbid;
	for (k = 0; k < n; k++) {
		pk_u64le(blob, i, values[k]); i += 8;
		blob[i++] = 2;
		blob[i++] = 0x51; /* OP_TRUE OP_TRUE: a two-byte script */
		blob[i++] = (unsigned char)(0x51 + (k & 1));
	}
	return i;
}

static void r3_parse_sentinel(T_DATUM_STRATUM_JOB *job) {
	job->available_coinbase_outputs_count = 7;
	job->datum_coinbaser_id = 0x55;
	job->available_coinbase_outputs[0].value_sats = 4242;
	job->available_coinbase_outputs[1].value_sats = 4343;
}

static bool r3_parse_untouched(const T_DATUM_STRATUM_JOB *job) {
	return (job->available_coinbase_outputs_count == 7) && (job->datum_coinbaser_id == 0x55) &&
		(job->available_coinbase_outputs[0].value_sats == 4242) && (job->available_coinbase_outputs[1].value_sats == 4343);
}

static void datum_r3_parser_tests(void) {
	T_DATUM_STRATUM_JOB *job = calloc(1, sizeof(*job));
	unsigned char *blob = malloc(32768);
	uint64_t values[DATUM_COINBASER_MAX_OUTPUTS + 1];
	int len, k;

	datum_test(job != NULL && blob != NULL);
	if (!job || !blob) goto out;

	/* Regression: reward 100, outputs 3 then 101. The second output does not fit, so
	 * the reply is rejected whole: no part of it is accepted and the job is untouched. */
	job->coinbase_value = 100;
	values[0] = 3; values[1] = 101;
	len = r3_blob_outputs(blob, 7, values, 2);
	r3_parse_sentinel(job);
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == -1);
	datum_test(r3_parse_untouched(job));
	datum_test(datum_coinbaser_outputs_decision(datum_coinbaser_v2_parse(job, blob, len, false), true) == -1);

	/* The same reply with a second output that fits exactly is accepted whole. */
	values[1] = 97;
	len = r3_blob_outputs(blob, 7, values, 2);
	r3_parse_sentinel(job);
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == 2);
	datum_test(job->available_coinbase_outputs_count == 2);
	datum_test(job->datum_coinbaser_id == 7);
	datum_test(job->available_coinbase_outputs[0].value_sats == 3);
	datum_test(job->available_coinbase_outputs[1].value_sats == 97);
	datum_test(job->available_coinbase_outputs[1].output_script_len == 2);
	datum_test(job->available_coinbase_outputs[1].output_script[1] == 0x52);

	/* Overflow: 50 then UINT64_MAX - 10. The old (tally + outval) wrapped to 39 <= 100
	 * and accepted it; the remaining-value comparison cannot wrap. */
	values[0] = 50; values[1] = UINT64_MAX - 10;
	len = r3_blob_outputs(blob, 7, values, 2);
	r3_parse_sentinel(job);
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == -1);
	datum_test(r3_parse_untouched(job));
	values[0] = UINT64_MAX;
	len = r3_blob_outputs(blob, 7, values, 1);
	r3_parse_sentinel(job);
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == -1);
	datum_test(r3_parse_untouched(job));

	/* Exactly at the cap: 512 outputs are accepted... */
	job->coinbase_value = 1000000;
	for (k = 0; k <= DATUM_COINBASER_MAX_OUTPUTS; k++) values[k] = 1;
	len = r3_blob_outputs(blob, 9, values, DATUM_COINBASER_MAX_OUTPUTS);
	r3_parse_sentinel(job);
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == DATUM_COINBASER_MAX_OUTPUTS);
	datum_test(job->available_coinbase_outputs_count == DATUM_COINBASER_MAX_OUTPUTS);
	/* ...one more is not silently cut to 512: the reply is rejected whole. */
	len = r3_blob_outputs(blob, 9, values, DATUM_COINBASER_MAX_OUTPUTS + 1);
	r3_parse_sentinel(job);
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == -1);
	datum_test(r3_parse_untouched(job));

	/* Trailing bytes after the last complete output (short of an output, or an
	 * output-sized tail that is not one) are rejected, not ignored. */
	values[0] = 5;
	len = r3_blob_outputs(blob, 7, values, 1);
	blob[len] = 0xAA; blob[len + 1] = 0xBB; blob[len + 2] = 0xCC;
	r3_parse_sentinel(job);
	datum_test(datum_coinbaser_v2_parse(job, blob, len + 3, false) == -1);
	datum_test(r3_parse_untouched(job));
	memset(blob + len, 0, 9);
	r3_parse_sentinel(job);
	datum_test(datum_coinbaser_v2_parse(job, blob, len + 9, false) == -1); /* script length 0 */
	datum_test(r3_parse_untouched(job));

	/* Bad script lengths and a script cut short. */
	len = r3_blob_outputs(blob, 7, values, 1);
	blob[9] = 1;
	r3_parse_sentinel(job);
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == -1);
	datum_test(r3_parse_untouched(job));
	blob[9] = 65;
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == -1);
	blob[9] = 2;
	datum_test(datum_coinbaser_v2_parse(job, blob, len - 1, false) == -1);
	datum_test(r3_parse_untouched(job));

	/* The coinbaser ID alone: a well-formed reply with no payout outputs (0). */
	r3_parse_sentinel(job);
	datum_test(datum_coinbaser_v2_parse(job, blob, 1, false) == 0);
	datum_test(job->available_coinbase_outputs_count == 0);
	datum_test(datum_coinbaser_outputs_decision(0, true) == -1);

out:
	free(blob);
	free(job);
}

/* ---- the publication check on the coinbase miners are actually served ---- */

static void datum_r3_validator_tests(void) {
	const global_config_t saved_config = datum_config;
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_POOLED_SETTLEMENT settle;
	T_DATUM_STRATUM_JOB *job;
	T_R3_OUT *outs = calloc(600, sizeof(*outs));
	unsigned char blob[4096];
	int len, n, k, ops_k;

	datum_test(outs != NULL);
	if (!outs) return;
	r3_config_pooled();
	r3_settlement(&settle, 5);
	r3_template_init(&tdata, R3_VALUE);

	/* Complete: 75 miners + the pool's own line, covering every satoshi. */
	job = r3_job_new(&tdata, 3, 1);
	datum_test(job != NULL);
	if (!job) goto out;
	len = r3_assignment_blob(blob, R3_VALUE, 75, true, 42);
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == 76);
	datum_test(generate_coinbase_txns_for_stratum_job_pooled(job, &settle));
	datum_test(job->is_datum_job);
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_OK);
	/* what the check accepted, decoded independently: 76 assigned + dead OP_RETURN + commitment, no pool output */
	n = r3_decode(job, COINBASE_TYPE_YUGE, outs, 600);
	datum_test(n == 78);
	ops_k = r3_find(outs, n, r3_ops_script, sizeof(r3_ops_script));
	datum_test(ops_k >= 0);
	datum_test(r3_find(outs, n, r3_local_pool_script, sizeof(r3_local_pool_script)) < 0);

	/* Wrong amount: one output carries a satoshi more and another one less (the
	 * total is unchanged): those outputs are not the assignment's. */
	r3_patch_value(job, COINBASE_TYPE_YUGE, outs[0].value_off, outs[0].value + 1);
	r3_patch_value(job, COINBASE_TYPE_YUGE, outs[1].value_off, outs[1].value - 1);
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_EXTRA_OUTPUT);
	r3_patch_value(job, COINBASE_TYPE_YUGE, outs[0].value_off, outs[0].value);
	r3_patch_value(job, COINBASE_TYPE_YUGE, outs[1].value_off, outs[1].value);
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_OK);

	/* Extra output: an assigned value sent to a script that is not in the assignment. */
	{
		unsigned char b = (unsigned char)(outs[2].script[5] ^ 0x80);
		r3_patch(job, COINBASE_TYPE_YUGE, outs[2].value_off + 9 + 5, &b, 1);
		datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_EXTRA_OUTPUT);
		b = outs[2].script[5];
		r3_patch(job, COINBASE_TYPE_YUGE, outs[2].value_off + 9 + 5, &b, 1);
	}

	/* Non-zero OP_RETURN: the witness commitment (last output) carries a satoshi. */
	r3_patch_value(job, COINBASE_TYPE_YUGE, outs[n - 1].value_off, 1);
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_NONZERO_OP_RETURN);
	r3_patch_value(job, COINBASE_TYPE_YUGE, outs[n - 1].value_off, 0);

	/* Missing pool output: the coinbase value grew after the build, so the check
	 * expects the unassigned remainder on the pool script, and there is none. */
	job->coinbase_value = R3_VALUE + 1000;
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_POOL_AMOUNT);
	job->coinbase_value = R3_VALUE;

	/* Malformed: the transaction cut short. */
	job->coinbase[COINBASE_TYPE_YUGE].coinb2_len--;
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_MALFORMED);
	job->coinbase[COINBASE_TYPE_YUGE].coinb2_len++;
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_OK);

	/* Nothing to check against. */
	k = job->available_coinbase_outputs_count;
	job->available_coinbase_outputs_count = 0;
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_NO_ASSIGNMENT);
	job->available_coinbase_outputs_count = k;

	/* The "empty" coinbase class (TINY: the pool script alone, without the
	 * assignment's outputs) copied into YUGE fails the check. */
	job->coinbase[COINBASE_TYPE_YUGE] = job->coinbase[COINBASE_TYPE_TINY];
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) != DATUM_CB_CHECK_OK);
	free(job);

	/* A remainder: an assignment without the pool's own line (97% of the value); the
	 * builder sends the rest to the pool script and the check wants exactly that. */
	job = r3_job_new(&tdata, 3, 2);
	datum_test(job != NULL);
	if (!job) goto out;
	len = r3_assignment_blob(blob, R3_VALUE, 10, false, 43);
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == 10);
	datum_test(generate_coinbase_txns_for_stratum_job_pooled(job, &settle));
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_OK);
	n = r3_decode(job, COINBASE_TYPE_YUGE, outs, 600);
	ops_k = r3_find(outs, n, r3_ops_script, sizeof(r3_ops_script));
	datum_test(ops_k >= 0);
	datum_test(outs[ops_k].value == R3_VALUE - ((R3_VALUE / 100) * 97 / 10) * 10);
	/* ...not a satoshi more */
	r3_patch_value(job, COINBASE_TYPE_YUGE, outs[ops_k].value_off, outs[ops_k].value + 1);
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_POOL_AMOUNT);
	r3_patch_value(job, COINBASE_TYPE_YUGE, outs[ops_k].value_off, outs[ops_k].value);
	/* ...and only to the settlement's pool script */
	settle.pool_script[5] ^= 1;
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_EXTRA_OUTPUT);
	settle.pool_script[5] ^= 1;
	free(job);

	/* Truncated: the template leaves room for only part of the assignment, so the
	 * built coinbase is incomplete and the check reports a missing output. */
	tdata.weightlimit = ((DATUM_BLAKE2B_BLOCK_HEADER_SIZE + 5) * 4) + 36 + (4 * (124 + 25 + 120 + 350));
	job = r3_job_new(&tdata, 3, 3);
	datum_test(job != NULL);
	if (!job) goto out;
	len = r3_assignment_blob(blob, R3_VALUE, 20, true, 44);
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == 21);
	datum_test(generate_coinbase_txns_for_stratum_job_pooled(job, &settle));
	n = r3_decode(job, COINBASE_TYPE_YUGE, outs, 600);
	datum_test(n > 0 && n < 21);
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_MISSING_OUTPUT);
	free(job);
	tdata.weightlimit = 4000000;

	/* Long tags: no room for the extranonce in the coinbase input, so it rides in
	 * a zero-value OP_RETURN in coinb1 — still a valid, complete coinbase. */
	/* 60 characters (the field holds 63): 4 + 1 + (9 + 60 + 2) + 11 = 87 bytes of input > 85 */
	strcpy(datum_config.mining_coinbase_tag_secondary,
		"012345678901234567890123456789012345678901234567890123456789");
	job = r3_job_new(&tdata, 3, 4);
	datum_test(job != NULL);
	if (!job) goto out;
	len = r3_assignment_blob(blob, R3_VALUE, 30, true, 45);
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == 31);
	datum_test(generate_coinbase_txns_for_stratum_job_pooled(job, &settle));
	n = r3_decode(job, COINBASE_TYPE_YUGE, outs, 600);
	datum_test(n == 34); /* extranonce OP_RETURN + 31 assigned + dead OP_RETURN + commitment */
	datum_test(outs[0].value == 0 && outs[0].len == 16 && outs[0].script[0] == 0x6a);
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_OK);
	r3_patch_value(job, COINBASE_TYPE_YUGE, outs[0].value_off, 5);
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_NONZERO_OP_RETURN);
	free(job);

out:
	free(outs);
	datum_config = saved_config;
}

/* ---- the builder itself refuses coinbases without an assignment in pooled-only mode ---- */

/* the live DATUM link as datum_protocol_is_active() sees it: configured, ABW assignment active */
static void r3_link_up(void) {
	unsigned char notice[36] = { DATUM_ABW_DRAFT_REVISION, DATUM_ABW_ASSIGNMENT_ACTIVE, 0 };
	memset(notice + 3, 0x5a, 32);
	notice[35] = 0xFE;
	atomic_store(&datum_protocol_client_active, 3);
	(void)datum_protocol_abw_assignment_notice(sizeof(notice), notice);
}

static void datum_r3_builder_boundary_tests(void) {
	const global_config_t saved_config = datum_config;
	const int saved_active = atomic_load(&datum_protocol_client_active);
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_POOLED_SETTLEMENT settle;
	T_DATUM_STRATUM_JOB *job;
	T_R3_OUT outs[8];
	unsigned char blob[4096];
	int len, n;

	r3_config_pooled();
	r3_settlement(&settle, 5);
	r3_template_init(&tdata, R3_VALUE);
	job = r3_job_new(&tdata, 3, 1);
	datum_test(job != NULL);
	if (!job) goto out;
	len = r3_assignment_blob(blob, R3_VALUE, 75, true, 42);
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == 76);

	/* Regression: after a good fetch the link is down when the (live)
	 * builder runs. Pooled-only: refused, and the job is left exactly as it was. */
	atomic_store(&datum_protocol_client_active, 0);
	generate_coinbase_txns_for_stratum_job(job, false);
	datum_test(job->coinbase[COINBASE_TYPE_YUGE].coinb1_len == 0);
	datum_test(job->coinbase[COINBASE_TYPE_YUGE].coinb2_len == 0);
	datum_test(!job->is_datum_job);
	datum_test(job->pool_addr_script_len == 0);
	/* With the link up: empty_only, or no payout outputs, is refused too. */
	r3_link_up();
	datum_test(datum_protocol_is_active());
	generate_coinbase_txns_for_stratum_job(job, true);
	datum_test(job->coinbase[COINBASE_TYPE_YUGE].coinb1_len == 0);
	n = job->available_coinbase_outputs_count;
	job->available_coinbase_outputs_count = 0;
	generate_coinbase_txns_for_stratum_job(job, false);
	datum_test(job->coinbase[COINBASE_TYPE_YUGE].coinb1_len == 0);
	datum_test(!job->is_datum_job);
	datum_test(!generate_coinbase_txns_for_stratum_job_pooled(job, &settle));
	datum_test(job->coinbase[COINBASE_TYPE_YUGE].coinb1_len == 0);
	job->available_coinbase_outputs_count = n;
	/* ...while the complete assignment builds, and passes the check */
	generate_coinbase_txns_for_stratum_job(job, false);
	datum_test(job->is_datum_job);
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_OK);
	datum_protocol_abw_reset();
	atomic_store(&datum_protocol_client_active, 0);
	memset(job->coinbase, 0, sizeof(job->coinbase));
	job->is_datum_job = false;
	/* no pool script in the settlement: refused */
	settle.pool_script_len = 0;
	datum_test(!generate_coinbase_txns_for_stratum_job_pooled(job, &settle));
	datum_test(job->coinbase[COINBASE_TYPE_YUGE].coinb1_len == 0);
	r3_settlement(&settle, 5);
	/* The pooled builder does not look at the link at all: the frozen settlement. */
	datum_test(generate_coinbase_txns_for_stratum_job_pooled(job, &settle));
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_OK);
	free(job);

	/* Solo (not pooled-only) keeps upstream's behaviour: with the link down the
	 * coinbase pays the local pool address everything, in every class. */
	datum_config.datum_pooled_mining_only = false;
	job = r3_job_new(&tdata, 3, 2);
	datum_test(job != NULL);
	if (!job) goto out;
	datum_test(datum_coinbaser_v2_parse(job, blob, len, false) == 76);
	job->available_coinbase_outputs_count = 0;
	generate_coinbase_txns_for_stratum_job(job, false);
	datum_test(!job->is_datum_job);
	n = r3_decode(job, COINBASE_TYPE_YUGE, outs, 8);
	datum_test(n == 2);
	datum_test(outs[0].value == R3_VALUE);
	datum_test(outs[0].len == (int)sizeof(r3_local_pool_script) && !memcmp(outs[0].script, r3_local_pool_script, sizeof(r3_local_pool_script)));
	datum_test(outs[1].value == 0 && outs[1].script[0] == 0x6a);
	datum_test(!strcmp(job->coinbase[COINBASE_TYPE_YUGE].coinb2, job->coinbase[COINBASE_TYPE_TINY].coinb2));
	free(job);

out:
	datum_protocol_abw_reset();
	atomic_store(&datum_protocol_client_active, saved_active);
	datum_config = saved_config;
}

/* ---- the per-job step with its outside world injected ---- */

typedef struct {
	bool link;                 /* what link_active() reports */
	uint64_t generation;       /* what session_generation() reports */
	uint64_t now;              /* what now_ms() reports */
	int fetch_calls;
	int fetch_result;          /* returned as is when !blob */
	const unsigned char *blob; /* else: parsed like a reply that arrived */
	int blob_len;
	bool drop_link_after_fetch;      /* the link goes down right after a good fetch... */
	bool new_session_after_fetch;    /* ...or a reconnect starts a new session */
	bool change_pool_after_fetch;    /* ...or the pool reconfigures its payout script */
} T_R3_IO;

static int r3_io_fetch(void *ctx, T_DATUM_STRATUM_JOB *s, uint64_t *request_generation) {
	T_R3_IO *io = ctx;
	int n;

	io->fetch_calls++;
	*request_generation = 0;
	s->available_coinbase_outputs_count = 0; /* as the real fetch does */
	if (!io->blob) return io->fetch_result;
	n = datum_coinbaser_v2_parse(s, (unsigned char *)io->blob, io->blob_len, false);
	if (n < 0) return DATUM_COINBASER_FETCH_REJECTED;
	*request_generation = io->generation;
	/* "paused after a successful fetch": what happens before the thread resumes */
	if (io->drop_link_after_fetch) io->link = false;
	if (io->new_session_after_fetch) io->generation++;
	if (io->change_pool_after_fetch) datum_config.override_mining_pool_scriptpubkey[4] ^= 0x01;
	return n;
}
static bool r3_io_link(void *ctx) { return ((T_R3_IO *)ctx)->link; }
static uint64_t r3_io_generation(void *ctx) { return ((T_R3_IO *)ctx)->generation; }
static uint64_t r3_io_now(void *ctx) { return ((T_R3_IO *)ctx)->now; }

static T_DATUM_COINBASER_IO r3_io(T_R3_IO *io) {
	T_DATUM_COINBASER_IO x = { r3_io_fetch, r3_io_link, r3_io_generation, r3_io_now, io };
	return x;
}

/* One stratum thread with one subscribed miner, driven through the real loop. */
typedef struct {
	T_DATUM_THREAD_DATA *my;
	T_DATUM_SOCKET_APP app;
	T_DATUM_STRATUM_THREADPOOL_DATA *sdata;
	T_DATUM_MINER_DATA *miner;
	T_DATUM_CLIENT_DATA *c;
} T_R3_STRATUM;

static bool r3_stratum_init(T_R3_STRATUM *st) {
	memset(st, 0, sizeof(*st));
	st->my = calloc(1, sizeof(*st->my)); /* large, but only a few pages are touched */
	st->sdata = calloc(1, sizeof(*st->sdata));
	st->miner = calloc(1, sizeof(*st->miner));
	if (!st->my || !st->sdata || !st->miner) return false;
	st->app.max_clients_thread = 1;
	st->app.max_threads = 1;
	st->my->app = &st->app;
	st->my->app_thread_data = st->sdata;
	st->sdata->latest_stratum_job_index = -1;
	st->sdata->next_kick_check_tsms = UINT64_MAX;
	st->c = &st->my->client_data[0];
	st->c->fd = 1; /* "connected": the loop only builds output, it never writes the fd */
	st->c->app_client_data = st->miner;
	st->c->datum_thread = st->my;
	st->miner->sdata = st->sdata;
	st->miner->subscribed = true;
	st->miner->current_diff = st->miner->last_sent_diff = 65536;
	st->miner->share_snap_tsms = current_time_millis();
	return true;
}

static void r3_stratum_free(T_R3_STRATUM *st) {
	free(st->my);
	free(st->sdata);
	free(st->miner);
}

static bool r3_out_has_notify(const T_DATUM_CLIENT_DATA *c) {
	static const char needle[] = "\"method\":\"mining.notify\"";
	int i;
	for (i = 0; i + (int)sizeof(needle) - 1 <= c->out_buf; i++) {
		if (!memcmp(c->w_buffer + i, needle, sizeof(needle) - 1)) return true;
	}
	return false;
}

/* Runs one pass of the real stratum thread loop with job as the gateway's
 * current job, then what a miner subscribing now would get; returns the notify
 * bytes queued for the existing miner (the subscribe probe must add none unless
 * the loop sent some too). */
static int r3_stratum_pass(T_R3_STRATUM *st, T_DATUM_STRATUM_JOB *job, bool *new_miner_got_work) {
	const int saved_latest = global_latest_stratum_job_index;
	T_DATUM_STRATUM_JOB * const saved_slot = global_cur_stratum_jobs[job->global_index];
	int loop_bytes, before;

	global_cur_stratum_jobs[job->global_index] = job;
	global_latest_stratum_job_index = job->global_index;
	st->c->out_buf = 0;
	datum_stratum_v1_socket_thread_loop(st->my);
	loop_bytes = st->c->out_buf;
	before = st->c->out_buf;
	/* client_mining_subscribe's clean-work notify */
	(void)send_mining_notify(st->c, true, false, false);
	*new_miner_got_work = (st->c->out_buf > before);
	st->c->out_buf = loop_bytes;
	global_latest_stratum_job_index = saved_latest;
	global_cur_stratum_jobs[job->global_index] = saved_slot;
	return loop_bytes;
}

static void datum_r3_step_tests(void) {
	const global_config_t saved_config = datum_config;
	const bool saved_init_done = need_coinbaser_rwlocks_init_done;
	T_DATUM_TEMPLATE_DATA tdata;
	T_DATUM_POOLED_SETTLEMENT settle;
	T_DATUM_STRATUM_JOB *job = NULL;
	T_R3_STRATUM st;
	T_R3_IO fio;
	T_DATUM_COINBASER_IO io;
	unsigned char blob[4096];
	bool new_miner_got_work = true;
	int len, bytes;
	/* the real stratum loop reads the real monotonic clock: keep the fake one in step with it */
	const uint64_t t_start = monotonic_time_millis();

	if (!datum_test(r3_stratum_init(&st))) goto out;
	r3_rwlocks_init();
	r3_config_pooled();
	r3_settlement(&settle, 41);
	r3_template_init(&tdata, R3_VALUE);
	len = r3_assignment_blob(blob, R3_VALUE, 75, true, 42);
	datum_pooled_outage_reset();

	/* Regression sequence: the link is up and the fetch returns the
	 * complete, legitimate assignment; the coinbaser thread is paused right after
	 * it; the link drops; the thread resumes and builds. The builder must not take
	 * the no-pool branch here (a coinbase without the assignment) or clear
	 * need_coinbaser. Expected: nothing is published and no miner gets a byte of it. */
	job = r3_job_new(&tdata, 9, 1001);
	if (!datum_test(job != NULL)) goto out;
	memset(&fio, 0, sizeof(fio));
	fio.link = true; fio.generation = 41; fio.now = t_start;
	fio.blob = blob; fio.blob_len = len;
	fio.drop_link_after_fetch = true;
	io = r3_io(&fio);
	datum_test(datum_coinbaser_job_step(job, &io) == DATUM_COINBASER_STEP_WAIT);
	datum_test(fio.fetch_calls == 1);
	datum_test(job->need_coinbaser == true);
	bytes = r3_stratum_pass(&st, job, &new_miner_got_work);
	datum_test(bytes == 0);
	datum_test(!r3_out_has_notify(st.c));
	datum_test(!new_miner_got_work);
	datum_test(datum_pooled_outage_since() == t_start);

	/* The same with a reconnect (new session) instead of a plain drop. */
	fio.drop_link_after_fetch = false;
	fio.link = true;
	fio.new_session_after_fetch = true;
	fio.now = t_start + 5;
	datum_test(datum_coinbaser_job_step(job, &io) == DATUM_COINBASER_STEP_WAIT);
	datum_test(fio.generation == 42);
	datum_test(job->need_coinbaser == true);
	bytes = r3_stratum_pass(&st, job, &new_miner_got_work);
	datum_test(bytes == 0 && !new_miner_got_work);

	/* The pool changes its payout script mid-flight: stale too. */
	fio.new_session_after_fetch = false;
	fio.change_pool_after_fetch = true;
	datum_test(datum_coinbaser_job_step(job, &io) == DATUM_COINBASER_STEP_WAIT);
	datum_test(job->need_coinbaser == true);
	datum_config.override_mining_pool_scriptpubkey[4] ^= 0x01;
	fio.change_pool_after_fetch = false;

	/* Link down: nothing is fetched, nothing built. */
	fio.link = false;
	datum_test(datum_coinbaser_job_step(job, &io) == DATUM_COINBASER_STEP_WAIT);
	datum_test(fio.fetch_calls == 3);
	datum_test(job->need_coinbaser == true);

	/* Link up but no usable coinbaser: no reply, an empty one, a rejected one. */
	fio.link = true;
	fio.blob = NULL;
	fio.fetch_result = DATUM_COINBASER_FETCH_NO_REPLY;
	datum_test(datum_coinbaser_job_step(job, &io) == DATUM_COINBASER_STEP_WAIT);
	fio.fetch_result = 0;
	datum_test(datum_coinbaser_job_step(job, &io) == DATUM_COINBASER_STEP_BACKOFF);
	fio.fetch_result = DATUM_COINBASER_FETCH_REJECTED;
	datum_test(datum_coinbaser_job_step(job, &io) == DATUM_COINBASER_STEP_BACKOFF);
	datum_test(job->need_coinbaser == true);
	bytes = r3_stratum_pass(&st, job, &new_miner_got_work);
	datum_test(bytes == 0 && !new_miner_got_work);
	datum_test(datum_pooled_outage_since() == t_start); /* none of that ended the outage */

	/* A complete assignment the template cannot hold: withheld (truncation). */
	tdata.weightlimit = ((DATUM_BLAKE2B_BLOCK_HEADER_SIZE + 5) * 4) + 36 + (4 * (124 + 25 + 120 + 350));
	fio.blob = blob; fio.blob_len = len;
	datum_test(datum_coinbaser_job_step(job, &io) == DATUM_COINBASER_STEP_BACKOFF);
	datum_test(job->need_coinbaser == true);
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_MISSING_OUTPUT);
	bytes = r3_stratum_pass(&st, job, &new_miner_got_work);
	datum_test(bytes == 0 && !new_miner_got_work);
	tdata.weightlimit = 4000000;

	/* Resume properly: the link is up on the session the request goes out on. */
	fio.now = t_start + 30;
	datum_test(datum_coinbaser_job_step(job, &io) == DATUM_COINBASER_STEP_PUBLISHED);
	datum_test(job->need_coinbaser == false);
	datum_test(job->coinbaser_session_generation == 42);
	datum_test(datum_coinbaser_pooled_coinbase_check(job, COINBASE_TYPE_YUGE, &settle) == DATUM_CB_CHECK_OK);
	datum_test(datum_pooled_outage_since() == 0);
	/* positive control: the same harness now sees the work go out, as YUGE */
	bytes = r3_stratum_pass(&st, job, &new_miner_got_work);
	datum_test(bytes > 0);
	datum_test(r3_out_has_notify(st.c));
	datum_test(new_miner_got_work);
	{
		static const char yuge_id[] = "[\"04\",";
		bool found = false;
		int i;
		for (i = 0; i + (int)sizeof(yuge_id) - 1 <= st.c->out_buf; i++) {
			if (!memcmp(st.c->w_buffer + i, yuge_id, sizeof(yuge_id) - 1)) found = true;
		}
		datum_test(found);
	}
	free(job);
	job = NULL;

	/* Solo keeps upstream's step: link down, it builds on the local address and publishes. */
	datum_config.datum_pooled_mining_only = false;
	job = r3_job_new(&tdata, 10, 1002);
	if (!datum_test(job != NULL)) goto out;
	memset(&fio, 0, sizeof(fio));
	fio.link = false;
	io = r3_io(&fio);
	datum_test(datum_coinbaser_job_step(job, &io) == DATUM_COINBASER_STEP_PUBLISHED);
	datum_test(fio.fetch_calls == 0);
	datum_test(job->need_coinbaser == false);
	datum_test(!job->is_datum_job);
	datum_test(datum_pooled_outage_since() == 0);

out:
	free(job);
	r3_stratum_free(&st);
	datum_pooled_outage_reset();
	need_coinbaser_rwlocks_init_done = saved_init_done;
	datum_config = saved_config;
}

void datum_coinbaser_tests(void) {
	datum_prime_id_64bit_tests();
	datum_blake2b_coinbase_limit_tests();
	datum_blake2b_coinbase_sigops_tests();
	datum_r3_parser_tests();
	datum_r3_validator_tests();
	datum_r3_builder_boundary_tests();
	datum_r3_step_tests();
}
