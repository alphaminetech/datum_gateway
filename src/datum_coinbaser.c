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

// TODO: Empty work speedup work and an actual empty template will cause duplicate work.
// It's kind of unlikely that a sane miner would be purposefully providing empty templates, but
// this is a low priority bug to address nonetheless.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <curl/curl.h>
#include <inttypes.h>
#include <unistd.h>

#include "datum_conf.h"
#include "datum_pow.h"
#include "datum_utils.h"
#include "datum_stratum.h"
#include "datum_jsonrpc.h"
#include "datum_protocol.h"
#include "datum_coinbaser.h"

CURL *coinbaser_curl = NULL;

const char *cbstart_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff"; // 82 len hex, 41 bytes

// datum_active selects the pool's tags (and the Prime ID form of the unique ID
// push) exactly as the live link state does in generate_coinbase_input().
static int generate_coinbase_input_ex(int height, char *cb, int *target_pot_index, bool datum_active) {
	int cb_input_sz = 0;
	int tag_len[2] = { 0, 0 };
	int k, m, i;
	int excess;
	
	// let's figure out our coinbase tags w/BIP34 height
	i = append_UNum_hex(height, &cb[0]);
	cb_input_sz += i>>1;
	
	// Handle coinbase tagging
	// The first push after the height should be:
	// PUSHBYTES X, Primary tag, 0x0F, Secondary tag, 0x0F, Tertiary tag, 0x00
	// We should then push a unique entropy tag (push + 2 bytes = 3 bytes)
	if (!datum_active) {
		tag_len[0] = strlen(datum_config.mining_coinbase_tag_primary);
	} else {
		tag_len[0] = strlen(datum_config.override_mining_coinbase_tag_primary);
	}
	tag_len[1] = strlen(datum_config.mining_coinbase_tag_secondary);
	k = tag_len[0] + tag_len[1] + 2;
	if (!tag_len[1]) {
		k--;
		if (!tag_len[0]) {
			k--;
		}
	}
	
	if (k > MAX_COINBASE_TAG_SPACE) {
		// something still needs truncating
		excess = k - MAX_COINBASE_TAG_SPACE;
		if (tag_len[1] > excess) {
			// truncating tag1 is enough to cover us
			tag_len[1] -= excess;
			k = MAX_COINBASE_TAG_SPACE;
		} else {
			// not enough, so need to remove this tag entirely
			if (tag_len[1]) {
				tag_len[1] = 0;
				k-=tag_len[1]+1;
			}
		}
	}
	
	if (k > MAX_COINBASE_TAG_SPACE) {
		// one tag should never exceed 64 bytes, so we're going to panic here.
		DLOG_FATAL("Could not fit coinbase primary tag alone somehow. This is probably a bug. Panicking. :(");
		panic_from_thread(__LINE__);
		sleep(1000000);
	}
	
	if (k > 0) {
		// ok, we have one or more coinbase tags with a total len of k
		if (k <= 75) {
			// OP_PUSHBYTES (1 byte, 1 to 75)
			uchar_to_hex(&cb[i], (unsigned char)k); i+=2; cb_input_sz++;
		} else {
			// OP_PUSHBYTES (2 byte, 76 to 94)
			uchar_to_hex(&cb[i], 0x4C); i+=2; cb_input_sz++;
			uchar_to_hex(&cb[i], (unsigned char)k); i+=2; cb_input_sz++;
		}
		
		if (tag_len[0]) {
			if (datum_active) {
				for(m=0;m<tag_len[0];m++) {
					uchar_to_hex(&cb[i], (unsigned char)datum_config.override_mining_coinbase_tag_primary[m]); i+=2; cb_input_sz++;
				}
			} else {
				for(m=0;m<tag_len[0];m++) {
					uchar_to_hex(&cb[i], (unsigned char)datum_config.mining_coinbase_tag_primary[m]); i+=2; cb_input_sz++;
				}
			}
			if (!tag_len[1]) {
				uchar_to_hex(&cb[i], 0x00); i+=2; cb_input_sz++;
			} else {
				uchar_to_hex(&cb[i], 0x0F); i+=2; cb_input_sz++;
			}
		} else {
			// we wouldn't be here if there wasn't at least one other
			if (tag_len[1]) {
				uchar_to_hex(&cb[i], 0x0F); i+=2; cb_input_sz++;
			}
		}
		
		if (tag_len[1]) {
			for(m=0;m<tag_len[1];m++) {
				uchar_to_hex(&cb[i], (unsigned char)datum_config.mining_coinbase_tag_secondary[m]); i+=2; cb_input_sz++;
			}
			uchar_to_hex(&cb[i], 0x00); i+=2; cb_input_sz++;
		}
	} else {
		// we'll push a null char to be consistent, and to not parse the UID as if it were a pool name
		uchar_to_hex(&cb[i], 0x01); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], 0x00); i+=2; cb_input_sz++;
	}
	
	// append the coinbase unique ID tag
	if ((datum_config.prime_id == 0) && (!datum_active)) {
		uchar_to_hex(&cb[i], 0x03); i+=2; cb_input_sz++;
		if (target_pot_index != NULL) *target_pot_index = cb_input_sz;
		uchar_to_hex(&cb[i], 0xFF); i+=2; cb_input_sz++; // placehodler for PoT target
		uchar_to_hex(&cb[i], (datum_config.coinbase_unique_id&0xFF)); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], ((datum_config.coinbase_unique_id>>8)&0xFF)); i+=2; cb_input_sz++;
	} else {
		// AlphaPool: a pool id that fits in 32 bits is written in the classic 7-byte form
		// (PoT, unique id, 4-byte pool id) — byte-identical to what other DATUM gateway builds
		// put on chain, so block explorers that recognise pooled DATUM coinbases by that
		// push credit these blocks too. Larger ids keep the 11-byte form.
		const bool prime_id_64 = (datum_config.prime_id >> 32) != 0;
		uchar_to_hex(&cb[i], prime_id_64 ? 0x0B : 0x07); i+=2; cb_input_sz++;
		if (target_pot_index != NULL) *target_pot_index = cb_input_sz;
		uchar_to_hex(&cb[i], 0xFF); i+=2; cb_input_sz++; // placeholder for PoT target
		uchar_to_hex(&cb[i], (datum_config.coinbase_unique_id&0xFF)); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], ((datum_config.coinbase_unique_id>>8)&0xFF)); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], (datum_config.prime_id&0xFF)); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], ((datum_config.prime_id>>8)&0xFF)); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], ((datum_config.prime_id>>16)&0xFF)); i+=2; cb_input_sz++;
		uchar_to_hex(&cb[i], ((datum_config.prime_id>>24)&0xFF)); i+=2; cb_input_sz++;
		if (prime_id_64) {
			uchar_to_hex(&cb[i], ((datum_config.prime_id>>32)&0xFF)); i+=2; cb_input_sz++;
			uchar_to_hex(&cb[i], ((datum_config.prime_id>>40)&0xFF)); i+=2; cb_input_sz++;
			uchar_to_hex(&cb[i], ((datum_config.prime_id>>48)&0xFF)); i+=2; cb_input_sz++;
			uchar_to_hex(&cb[i], ((datum_config.prime_id>>56)&0xFF)); i+=2; cb_input_sz++;
		}
	}
	
	return cb_input_sz;
}

int generate_coinbase_input(int height, char *cb, int *target_pot_index) {
	return generate_coinbase_input_ex(height, cb, target_pot_index, datum_protocol_is_active());
}

void generate_coinbase_txns_for_stratum_job_subtypebysize(T_DATUM_STRATUM_JOB *s, int coinbase_index, int remaining_size, bool space_for_en_in_coinbase, int *cb1idx, int *cb2idx, bool special_coinb1) {
	// This function finishes off the stratum coinb1+coinb2 using the available outputs in the job and other flags specified.
	// it does not attempt to maximize coinb1's size to any specific size
	
	int i, j, k, m, i2 = 0, c1cnt = 0;
	uint64_t mval = 0;
	bool c1full = false;
	bool en_done = false;
	// chicken and egg problem.  we need to know the output count before we can close off coinb1 if !space_for_en_in_coinbase
	// either way, we want to start out coinb2 with outputs
	i = remaining_size;
	j = remaining_size;
	if (special_coinb1) {
		i2 = (300 - cb1idx[coinbase_index])>>1;
		if (i2 < 0) i2 = 0;
		space_for_en_in_coinbase = false;
	}
	m = 0;
	mval = 0;
	// technically an output script could be > 0x4B, meaning an extra byte would be eaten here... but that's not currently the standard
	// this needs to match the loop lower in this function, as the count will get thrown off if it does not.
	
	// The sigop cost available to these outputs: the template's sigoplimit
	// (from GBT, in sigop cost units, where one legacy CHECKSIG counts 4) minus
	// the cost of the template's transactions and minus the cost of the pool's
	// own output. available_coinbase_outputs[].sigops is set by the coinbaser
	// parser: 4 for a script whose first byte is OP_DUP (0x76, P2PKH) and 0
	// for every other script. The pool output is charged the same way. An
	// output whose cost exceeds the remaining budget is skipped, the same as an
	// output that exceeds the remaining size, in both this counting pass and
	// the writing pass below.
	int64_t sigops_budget = (int64_t)s->block_template->sigoplimit - (int64_t)s->block_template->txn_total_sigops;
	if ((s->pool_addr_script_len > 0) && (s->pool_addr_script[0] == 0x76)) sigops_budget -= 4;
	if (sigops_budget < 0) sigops_budget = 0;
	int64_t sigops_left = sigops_budget;
	for(k=0;k<s->available_coinbase_outputs_count;k++) {
		if (((s->available_coinbase_outputs[k].output_script_len+9) <= i) && ((mval + s->available_coinbase_outputs[k].value_sats) <= s->coinbase_value) && (s->available_coinbase_outputs[k].sigops <= sigops_left))  {
			if ((special_coinb1) && (!c1full) && ((s->available_coinbase_outputs[k].output_script_len+9) <= i2)) {
				i2 -= (s->available_coinbase_outputs[k].output_script_len+9);
				c1cnt++;
			} else {
				c1full = true;
			}
			
			i -= (s->available_coinbase_outputs[k].output_script_len+9);
			sigops_left -= s->available_coinbase_outputs[k].sigops;
			m++;
			mval += s->available_coinbase_outputs[k].value_sats;
			if (i < 30) break;
			if (mval >= s->coinbase_value) break;
		}
	}
	
	// "m" outputs fit
	if (space_for_en_in_coinbase) {
		// we'll start the empty coinb2 with the "sequence"
		m+=2; // pool addr + witness
		pk_u64le(s->coinbase[coinbase_index].coinb2, cb2idx[coinbase_index], 0x6666666666666666ULL);  // "ffffffff"
		cb2idx[coinbase_index] = 8;
		cb2idx[coinbase_index] += append_bitcoin_varint_hex(m, &s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]]); // us, witness, and "m" outputs
	} else {
		m+=3;
		cb1idx[coinbase_index] += append_bitcoin_varint_hex(m, &s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]]); // extranonce, us, witness commit, and "m" outputs
		
		if (!special_coinb1) {
			// append extranonce op_return
			cb1idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]], "0000000000000000106a0e%04" PRIx16, s->enprefix);
			en_done = true;
		}
	}
	
	// append "m" payouts. find them the same way we did before
	mval = 0;
	sigops_left = sigops_budget;
	for(k=0;k<s->available_coinbase_outputs_count;k++) {
		if (((s->available_coinbase_outputs[k].output_script_len+9) <= j) && ((mval + s->available_coinbase_outputs[k].value_sats) <= s->coinbase_value) && (s->available_coinbase_outputs[k].sigops <= sigops_left)) {
			j -= (s->available_coinbase_outputs[k].output_script_len+9);
			sigops_left -= s->available_coinbase_outputs[k].sigops;
			m--;
			
			mval += s->available_coinbase_outputs[k].value_sats;
			
			if ((special_coinb1) && (k < c1cnt)) {
				// put in coinb1
				cb1idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]], "%016llx", (unsigned long long)__builtin_bswap64(s->available_coinbase_outputs[k].value_sats)); // TODO: Profile a faster way to do this
				cb1idx[coinbase_index] += append_bitcoin_varint_hex(s->available_coinbase_outputs[k].output_script_len, &s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]]); // Append script length
				for(i=0;i<s->available_coinbase_outputs[k].output_script_len;i++) {
					uchar_to_hex(&s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]], s->available_coinbase_outputs[k].output_script[i]);
					cb1idx[coinbase_index]+=2;
				}
			} else {
				if ((special_coinb1) && (k == c1cnt)) {
					// append extranonce op_return
					cb1idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]], "0000000000000000106a0e%04" PRIx16, s->enprefix);
					en_done = true;
				}
				
				// put in coinb2
				cb2idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], "%016llx", (unsigned long long)__builtin_bswap64(s->available_coinbase_outputs[k].value_sats)); // TODO: Profile a faster way to do this
				cb2idx[coinbase_index] += append_bitcoin_varint_hex(s->available_coinbase_outputs[k].output_script_len, &s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]]); // Append script length
				for(i=0;i<s->available_coinbase_outputs[k].output_script_len;i++) {
					uchar_to_hex(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], s->available_coinbase_outputs[k].output_script[i]);
					cb2idx[coinbase_index]+=2;
				}
			}
			if (!m) break;
			if (j < 30) break;
			if (mval >= s->coinbase_value) break;
		}
	}
	
	// this should never happen, but...
	if (mval > s->coinbase_value) {
		DLOG_ERROR("Attempting to pay more than we have available in the generation txn! --- %"PRIu64" sats available, %"PRIu64" sats to miners", s->coinbase_value, mval);
	}
	
	if ((!space_for_en_in_coinbase) && (!en_done)) {
		cb1idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb1[cb1idx[coinbase_index]], "0000000000000000106a0e%04" PRIx16, s->enprefix);
		en_done = true;
	}
	
	if (s->coinbase_value > mval) {
		// append our payout output value and script, since there are leftover funds
		cb2idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], "%016llx", (unsigned long long)__builtin_bswap64(s->coinbase_value - mval)); // TODO: Profile a faster way to do this
		cb2idx[coinbase_index] += append_bitcoin_varint_hex(s->pool_addr_script_len, &s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]]); // Append script length
		for(i=0;i<s->pool_addr_script_len;i++) {
			uchar_to_hex(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], s->pool_addr_script[i]);
			cb2idx[coinbase_index]+=2;
		}
	} else {
		// We paid every sat of the coinbase to miners... and saved an output.
		// HOWEVER....... we already locked in a number of outputs that presumes we would have a pool output
		// so tack on a dead output, sadly.
		// TODO: Make code smarter above, don't waste an output if we don't need it.
		// This is quite unlikely in practice, but, just in case let's make this a prunable OP_RETURN
		cb2idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], "0000000000000000036a0100"); // TODO: Is a naked OP_RETURN without any bytes after safe?  Above TODO is probably better than investigating.
	}
	
	// witness commitment output costs 47 bytes (8 value, 1 length, 38 script)
	// append the default_witness_commitment
	cb2idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], "0000000000000000%2.2x%s", (unsigned int)strlen(s->block_template->default_witness_commitment)>>1, s->block_template->default_witness_commitment);
	// lock time
	cb2idx[coinbase_index] += sprintf(&s->coinbase[coinbase_index].coinb2[cb2idx[coinbase_index]], "00000000");
}

int datum_stratum_coinbase_fit_to_template(int max_sz, int fixed_bytes, T_DATUM_STRATUM_JOB *s) {
	int j,i,msz1;
	
	i = fixed_bytes + max_sz;
	msz1 = max_sz+fixed_bytes;
	
	if ((i+s->block_template->txn_total_size+DATUM_BLAKE2B_BLOCK_HEADER_SIZE+5+36) > s->block_template->sizelimit) {
		j = s->block_template->sizelimit - (s->block_template->txn_total_size+DATUM_BLAKE2B_BLOCK_HEADER_SIZE+5+36) - fixed_bytes;
		if (j < 0) return 0;
		msz1 = j;
	}
	
	// Block weight: four units a byte for the header and the transaction count
	// (at most five bytes), four a byte for the coinbase (no witness data of
	// its own) plus the 36 bytes of witness the node adds to it (marker, flag,
	// one 32-byte item), and the template's transactions at their weight. The
	// original 340 covered the 80-byte SHA256d header.
	if (((i<<2)+s->block_template->txn_total_weight+((DATUM_BLAKE2B_BLOCK_HEADER_SIZE+5)<<2)+36) > s->block_template->weightlimit) {
		j = ((s->block_template->weightlimit - (s->block_template->txn_total_weight+((DATUM_BLAKE2B_BLOCK_HEADER_SIZE+5)<<2)+36))>>2) - fixed_bytes;
		if (j < 0) return 0;
		msz1 = j;
	}
	
	if (msz1 < 0) {
		msz1 = 0;
	}
	
	if (msz1 < (max_sz - fixed_bytes)) {
		return msz1;
	} else {
		return max_sz - fixed_bytes;
	}
}

void generate_base_coinbase_txns_for_stratum_job(T_DATUM_STRATUM_JOB *s, bool new_block) {
	char cb[512];
	int cb_input_sz = 0;
	bool space_for_en_in_coinbase = false;
	int i, j, k;
	int cb1idx[1] = { 0 };
	int cb2idx[1] = { 0 };
	int target_pot_index;
	
	if (datum_protocol_is_active()) {
		// DATUM
		s->pool_addr_script_len = datum_config.override_mining_pool_scriptpubkey_len;
		memcpy(&s->pool_addr_script[0], datum_config.override_mining_pool_scriptpubkey, datum_config.override_mining_pool_scriptpubkey_len);
		s->is_datum_job = true;
	} else {
		// No pool
		s->pool_addr_script_len = addr_2_output_script(datum_config.mining_pool_address, &s->pool_addr_script[0], 64);
		s->is_datum_job = false;
	}
	if (!s->pool_addr_script_len) {
		DLOG_FATAL("Could not generate output script for pool addr! Perhaps invalid? This is bad.");
		panic_from_thread(__LINE__);
	}
	// copy beginning of the generation txn to the appropriate outputs
	j = strlen(cbstart_hex);
	memcpy(&s->coinbase[0].coinb1[0], cbstart_hex, j);
	cb1idx[0] = j;
	
	cb_input_sz = generate_coinbase_input(s->height, &cb[0], &target_pot_index);
	i = cb_input_sz << 1;
	
	// null terminate... probably not needed
	cb[i] = 0;
	
	if (cb_input_sz <= 85) {
		space_for_en_in_coinbase = true;
	}
	
	if (space_for_en_in_coinbase) {
		cb1idx[0] += append_bitcoin_varint_hex(cb_input_sz+15, &s->coinbase[0].coinb1[cb1idx[0]]); // 15 bytes for extranonce+uid push + data
	} else {
		cb1idx[0] += append_bitcoin_varint_hex(cb_input_sz, &s->coinbase[0].coinb1[cb1idx[0]]);
	}
	memcpy(&s->coinbase[0].coinb1[cb1idx[0]], &cb[0], cb_input_sz*2);
	s->target_pot_index = target_pot_index + (cb1idx[0]>>1); // adjust for placement in the txn. always safe for all types, since the varint will always be 1 byte.
	cb1idx[0] += cb_input_sz*2;
	
	if (space_for_en_in_coinbase) {
		// if we are doing extranonce in the coinbase, then this is ALMOST the end of coinbase1
		// we need a PUSH 14 and our enprefix in the coinbase
		uchar_to_hex(&s->coinbase[0].coinb1[cb1idx[0]], 0x0E);
		cb1idx[0]+=2;
		// TODO: Profile a faster way to do this
		cb1idx[0] += sprintf(&s->coinbase[0].coinb1[cb1idx[0]], "%04" PRIx16, s->enprefix);
	} else {
		// if we are not, then we need to append the "sequence"
		pk_u64le(s->coinbase[0].coinb1, cb1idx[0], 0x6666666666666666ULL);  // "ffffffff"
		cb1idx[0] += 8;
	}
	
	s->coinbase[0].coinb1[cb1idx[0]] = 0;
	
	/////////////////////////////
	// 0 / EMPTY
	// empty should be easy. lets start there
	if (space_for_en_in_coinbase) {
		// we'll start the empty coinb2 with the "sequence"
		pk_u64le(s->coinbase[0].coinb2, 0, 0x6666666666666666ULL);  // "ffffffff"
		cb2idx[0] = 8;
		cb2idx[0] += append_bitcoin_varint_hex(2, &s->coinbase[0].coinb2[cb2idx[0]]); // us and witness commit
		
		if (new_block) {
			// copy the beginning to the subsidy-only
			memcpy(&s->subsidy_only_coinbase.coinb1[0], &s->coinbase[0].coinb1[0], cb1idx[0]);
			pk_u64le(s->subsidy_only_coinbase.coinb2, 0, 0x6666666666666666ULL);  // "ffffffff"
			append_bitcoin_varint_hex(1, &s->subsidy_only_coinbase.coinb2[8]); // just us!
		}
	} else {
		// we're already at the point in coinb1 where we need an output count, which will be 3
		if (new_block) {
			j = cb1idx[0];
		}
		cb1idx[0] += append_bitcoin_varint_hex(3, &s->coinbase[0].coinb1[cb1idx[0]]); // extranonce, us, and witness commit
		
		// append extranonce op_return
		cb1idx[0] += sprintf(&s->coinbase[0].coinb1[cb1idx[0]], "0000000000000000106a0e%04" PRIx16, s->enprefix);
		
		if (new_block) {
			// copy the beginning to the subsidy-only
			memcpy(&s->subsidy_only_coinbase.coinb1[0], &s->coinbase[0].coinb1[0], cb1idx[0]);
			k = append_bitcoin_varint_hex(2, &s->subsidy_only_coinbase.coinb1[j]); // extranonce and us
			s->subsidy_only_coinbase.coinb1[j+k] = s->coinbase[0].coinb1[j+k];
		}
	}
	// finish off "empty" coinbase
	
	// append our payout output value and script
	if (new_block) {
		j = cb2idx[0];
	}
	
	cb2idx[0] += sprintf(&s->coinbase[0].coinb2[cb2idx[0]], "%016llx", (unsigned long long)__builtin_bswap64(s->coinbase_value)); // TODO: Profile a faster way to do this
	cb2idx[0] += append_bitcoin_varint_hex(s->pool_addr_script_len, &s->coinbase[0].coinb2[cb2idx[0]]); // Append script length
	for(i=0;i<s->pool_addr_script_len;i++) {
		uchar_to_hex(&s->coinbase[0].coinb2[cb2idx[0]], s->pool_addr_script[i]);
		cb2idx[0]+=2;
	}
	
	if (new_block) {
		k = cb2idx[0];
	}
	
	// witness commitment output costs 47 bytes (8 value, 1 length, 38 script)
	// append the default_witness_commitment
	cb2idx[0] += sprintf(&s->coinbase[0].coinb2[cb2idx[0]], "0000000000000000%2.2x%s", (unsigned int)strlen(s->block_template->default_witness_commitment)>>1, s->block_template->default_witness_commitment);
	// lock time
	cb2idx[0] += sprintf(&s->coinbase[0].coinb2[cb2idx[0]], "00000000");
	
	if (new_block) {
		// Append the subsidy-only payout to the subsidy_only_coinbase
		sprintf(&s->subsidy_only_coinbase.coinb2[j], "%016llx", (unsigned long long)__builtin_bswap64(block_reward(s->height))); // subsidy calc for height
		memcpy(&s->subsidy_only_coinbase.coinb2[j+16], &s->coinbase[0].coinb2[j+16], k-j-16);
		sprintf(&s->subsidy_only_coinbase.coinb2[k], "00000000");
	}
	
	// End of 0 / Empty
	//////////////////////////////
	
	// prep binary versions of the coinbase for speeding up later
	
	i = strlen(s->coinbase[0].coinb1);
	s->coinbase[0].coinb1_len = 0;
	for(j=0;j<i;j+=2) {
		s->coinbase[0].coinb1_bin[j>>1] = hex2bin_uchar(&s->coinbase[0].coinb1[j]);
		s->coinbase[0].coinb1_len++;
	}
	i = strlen(s->coinbase[0].coinb2);
	s->coinbase[0].coinb2_len = 0;
	for(j=0;j<i;j+=2) {
		s->coinbase[0].coinb2_bin[j>>1] = hex2bin_uchar(&s->coinbase[0].coinb2[j]);
		s->coinbase[0].coinb2_len++;
	}
	
	if (new_block) {
		i = strlen(s->subsidy_only_coinbase.coinb1);
		s->subsidy_only_coinbase.coinb1_len = 0;
		for(j=0;j<i;j+=2) {
			s->subsidy_only_coinbase.coinb1_bin[j>>1] = hex2bin_uchar(&s->subsidy_only_coinbase.coinb1[j]);
			s->subsidy_only_coinbase.coinb1_len++;
		}
		i = strlen(s->subsidy_only_coinbase.coinb2);
		s->subsidy_only_coinbase.coinb2_len = 0;
		for(j=0;j<i;j+=2) {
			s->subsidy_only_coinbase.coinb2_bin[j>>1] = hex2bin_uchar(&s->subsidy_only_coinbase.coinb2[j]);
			s->subsidy_only_coinbase.coinb2_len++;
		}
	}
}

// Builds every coinbase class of job s from s->available_coinbase_outputs[].
// settle == NULL is upstream's behaviour: pool or no pool is decided from the
// LIVE link state, here and again in generate_coinbase_input(). settle != NULL
// (pooled-only) builds the DATUM coinbase with the settlement frozen when the
// assignment was requested and never consults the link.
// AlphaPool release 3: in pooled-only mode this is where a
// coinbase without the pool's assignment is refused, whoever the caller: the
// no-pool branch (local pool address) and empty_only (the pool output alone,
// copied into every class including YUGE) are not built from an assignment.
// Returns false, with the job untouched, when it refuses.
static bool generate_coinbase_txns_for_stratum_job_ex(T_DATUM_STRATUM_JOB *s, bool empty_only, const T_DATUM_POOLED_SETTLEMENT *settle) {
	// Account for available vsize, sigops, size, weight, etc
	
	// Note:
	// With a minimum payout of 10 TBC, the largest likely coinbase as of height 840000 is around 16 KB if we paid every miner the minimum to a long address type.
	// This seems highly unlikely.  16KB is more than sufficient.
	
	int i, j, k;
	char cb[300];
	int target_pot_index;
	int cb_input_sz = 0;
	
	bool space_for_en_in_coinbase = false;
	
	int cb1idx[MAX_COINBASE_TYPES] = { 0,0,0,0,0,0 };
	int cb2idx[MAX_COINBASE_TYPES] = { 0,0,0,0,0,0 };
	
	int cb_req_sz[MAX_COINBASE_TYPES] = { 0,0,0,0,0 };
	
	const bool datum_active = settle ? true : datum_protocol_is_active();
	
	if (!datum_active && !datum_coinbaser_local_fallback_allowed(false, datum_config.datum_pooled_mining_only)) {
		DLOG_ERROR("Pooled-only: refusing to build job %d's coinbase without the DATUM pool (there is no payout assignment to build it from)", s->global_index);
		return false;
	}
	if (datum_config.datum_pooled_mining_only && (empty_only || (s->available_coinbase_outputs_count <= 0))) {
		DLOG_ERROR("Pooled-only: refusing to build job %d's coinbase without the pool's payout outputs (a payout assignment is required)", s->global_index);
		return false;
	}
	if (settle && ((settle->pool_script_len <= 0) || (settle->pool_script_len > MAX_OUTPUT_SCRIPT_LEN))) {
		DLOG_ERROR("Pooled-only: no pool payout script for job %d's coinbase", s->global_index);
		return false;
	}
	
	////////////////
	
	// Initial mainnet coinbaser
	if (datum_active) {
		// DATUM
		if (settle) {
			s->pool_addr_script_len = settle->pool_script_len;
			memcpy(&s->pool_addr_script[0], settle->pool_script, settle->pool_script_len);
		} else {
			s->pool_addr_script_len = datum_config.override_mining_pool_scriptpubkey_len;
			memcpy(&s->pool_addr_script[0], datum_config.override_mining_pool_scriptpubkey, datum_config.override_mining_pool_scriptpubkey_len);
		}
		s->is_datum_job = true;
		if (s->available_coinbase_outputs_count == 0) {
			empty_only = true;
		}
	} else {
		// No pool
		s->pool_addr_script_len = addr_2_output_script(datum_config.mining_pool_address, &s->pool_addr_script[0], 64);
		s->is_datum_job = false;
		empty_only = true;
	}
	if (!s->pool_addr_script_len) {
		DLOG_FATAL("Could not generate output script for pool addr! Perhaps invalid? This is bad.");
		panic_from_thread(__LINE__);
	}
	
	// copy beginning of the generation txn to the appropriate outputs
	j = strlen(cbstart_hex);
	for(i=0;i<MAX_COINBASE_TYPES;i++) {
		memcpy(&s->coinbase[i].coinb1[0], cbstart_hex, j);
		cb1idx[i] = j;
	}
	
	if (settle) {
		cb_input_sz = generate_coinbase_input_ex(s->height, &cb[0], &target_pot_index, true);
	} else {
		cb_input_sz = generate_coinbase_input(s->height, &cb[0], &target_pot_index);
	}
	s->target_pot_index = target_pot_index;
	i = cb_input_sz << 1;
	
	// null terminate... probably not needed
	cb[i] = 0;
	
	// do we have space in the coinbase for the extranonce for types that can do it this way?
	// we need 1 byte for the push, 2 for the enprefix, 4 for en1 and 8 for en2 = 15 bytes
	// coinbase max is 100
	if (cb_input_sz <= 85) {
		space_for_en_in_coinbase = true;
	}
	
	// multiple coinbase options
	// 0 = "empty" --- just pays pool addr, and possibly TIDES data.  extranonce in coinbase if fits, or in first output if not.
	// 1 = "nicehash" --- roughly 500 bytes total... smaller than antminer... has nothing before the extranonce OP_RETURN (or no extranonce OP_RETURN if enough space in the coinbase)
	// 2 = "antminer" --- roughly 730 bytes max size, using a larger coinb1 and UART sync bits.  This also works as a good default.
	// 3 = "whatsminer" --- max 6500 bytes tested.  does not need the extranonce OP_RETURN unless there's no space in the coinbase itself after tags
	// 4 = "huge" --- max 16kB --- this is probably the most we should reasonably attempt to do in the coinbase... something like 380 to 530 outputs, depending on the type of output
	// 5 = "antminer2" --- max 2250 bytes --- latest S21s appear to support this
	
	// only type 2 *needs* the OP_RETURN extranonce, unless the coinbase itself is too long
	// set the len, and copy over the rest of the coinbase
	for(i=0;i<MAX_COINBASE_TYPES;i++) {
		if ((i!=2) && (space_for_en_in_coinbase)) {
			cb1idx[i] += append_bitcoin_varint_hex(cb_input_sz+15, &s->coinbase[i].coinb1[cb1idx[i]]);
		} else {
			cb1idx[i] += append_bitcoin_varint_hex(cb_input_sz, &s->coinbase[i].coinb1[cb1idx[i]]);
		}
		memcpy(&s->coinbase[i].coinb1[cb1idx[i]], &cb[0], cb_input_sz*2);
		// save this and adjust for placement in the txn... this is always safe because the coinbase input is always < 0xFD len
		// little silly to set this multiple times, but it's fine for consistency.
		s->target_pot_index = target_pot_index + (cb1idx[i]>>1);
		cb1idx[i] += cb_input_sz*2;
		
		if ((i!=2) && (space_for_en_in_coinbase)) {
			// if we are doing extranonce in the coinbase, then this is ALMOST the end of coinbase1
			// we need a PUSH 14 and our enprefix in the coinbase
			uchar_to_hex(&s->coinbase[i].coinb1[cb1idx[i]], 0x0E);
			cb1idx[i]+=2;
			// TODO: Profile a faster way to do this
			cb1idx[i] += sprintf(&s->coinbase[i].coinb1[cb1idx[i]], "%04" PRIx16, s->enprefix);
		} else {
			// if we are not, then we need to append the "sequence"
			pk_u64le(s->coinbase[i].coinb1, cb1idx[i], 0x6666666666666666ULL);  // "ffffffff"
			cb1idx[i] += 8;
		}
		
		s->coinbase[i].coinb1[cb1idx[i]] = 0;
	}
	
	// extranonce ends up at the end of coinb1
	// for the antminer hack coinbaser, we want to cram an output or two in coinb1, which is tricky
	// would be much easier to just always use the OP_RETURN, but that's wasteful when not needed as it wastes 10 bytes (wastes 8 bytes for the value, 2 for the OP_RETURN and the PUSH...)
	// if extranonce in the coinbase, then we start coinb2 with the "sequence"
	// if extranonce not in the coinbase, then we already tacked the "sequence" on to coinb1 immediately
	
	// we need to know the output count for each type so we can figure out what to stuff in each one
	// this may be a bit wasteful, but needs to be done.  only needs to happen once per work update, and only when doing non-empty.
	
	/////////////////////////////
	// 0 / EMPTY
	// empty should be easy. lets start there
	if (space_for_en_in_coinbase) {
		// we'll start the empty coinb2 with the "sequence"
		pk_u64le(s->coinbase[0].coinb2, 0, 0x6666666666666666ULL);  // "ffffffff"
		cb2idx[0] = 8;
		cb2idx[0] += append_bitcoin_varint_hex(2, &s->coinbase[0].coinb2[cb2idx[0]]); // us and witness commit
		
		if (empty_only) {
			// copy the beginning to the subsidy-only
			memcpy(&s->subsidy_only_coinbase.coinb1[0], &s->coinbase[0].coinb1[0], cb1idx[0]);
			pk_u64le(s->subsidy_only_coinbase.coinb2, 0, 0x6666666666666666ULL);  // "ffffffff"
			append_bitcoin_varint_hex(1, &s->subsidy_only_coinbase.coinb2[8]); // just us!
		}
	} else {
		// we're already at the point in coinb1 where we need an output count, which will be 3
		if (empty_only) {
			j = cb1idx[0];
		}
		cb1idx[0] += append_bitcoin_varint_hex(3, &s->coinbase[0].coinb1[cb1idx[0]]); // extranonce, us, and witness commit
		
		// append extranonce op_return
		cb1idx[0] += sprintf(&s->coinbase[0].coinb1[cb1idx[0]], "0000000000000000106a0e%04" PRIx16, s->enprefix);
		
		if (empty_only) {
			// copy the beginning to the subsidy-only
			memcpy(&s->subsidy_only_coinbase.coinb1[0], &s->coinbase[0].coinb1[0], cb1idx[0]);
			k = append_bitcoin_varint_hex(2, &s->subsidy_only_coinbase.coinb1[j]); // extranonce and us
			s->subsidy_only_coinbase.coinb1[j+k] = s->coinbase[0].coinb1[j+k];
		}
	}
	// finish off "empty" coinbase
	
	// append our payout output value and script
	if (empty_only) {
		j = cb2idx[0];
	}
	
	cb2idx[0] += sprintf(&s->coinbase[0].coinb2[cb2idx[0]], "%016llx", (unsigned long long)__builtin_bswap64(s->coinbase_value)); // TODO: Profile a faster way to do this
	cb2idx[0] += append_bitcoin_varint_hex(s->pool_addr_script_len, &s->coinbase[0].coinb2[cb2idx[0]]); // Append script length
	for(i=0;i<s->pool_addr_script_len;i++) {
		uchar_to_hex(&s->coinbase[0].coinb2[cb2idx[0]], s->pool_addr_script[i]);
		cb2idx[0]+=2;
	}
	
	if (empty_only) {
		k = cb2idx[0];
	}
	
	// witness commitment output costs 47 bytes (8 value, 1 length, 38 script)
	// append the default_witness_commitment
	cb2idx[0] += sprintf(&s->coinbase[0].coinb2[cb2idx[0]], "0000000000000000%2.2x%s", (unsigned int)strlen(s->block_template->default_witness_commitment)>>1, s->block_template->default_witness_commitment);
	// lock time
	cb2idx[0] += sprintf(&s->coinbase[0].coinb2[cb2idx[0]], "00000000");
	
	if (empty_only) {
		// Append the subsidy-only payout to the subsidy_only_coinbase
		sprintf(&s->subsidy_only_coinbase.coinb2[j], "%016llx", (unsigned long long)__builtin_bswap64(block_reward(s->height))); // subsidy calc for height
		memcpy(&s->subsidy_only_coinbase.coinb2[j+16], &s->coinbase[0].coinb2[j+16], k-j-16);
		sprintf(&s->subsidy_only_coinbase.coinb2[k], "00000000");
	}
	
	// End of 0 / Empty
	//////////////////////////////
	
	if (empty_only) {
		// copy empty coinbaser to the others
		for (i=1;i<MAX_COINBASE_TYPES;i++) {
			strcpy(s->coinbase[i].coinb1, s->coinbase[0].coinb1);
			strcpy(s->coinbase[i].coinb2, s->coinbase[0].coinb2);
		}
	} else {
		// ok, let's figure out how much space, if any, we have for miner payout outputs
		// we first need to figure out how much space we are using for each type after required data, so let's do that
		
		// witness commitment output = 47 bytes (8 value, 1 length, 38 script)
		// pool output = pool_addr_script_len + 9
		// coinbase itself = cb_input_sz
		// coinbase len = 1
		// cbstart = 41 bytes
		// lock time = 4 bytes
		// "sequence" = 4 bytes
		// extranonce size = 15 bytes (w/len push needed for either coinbase or OP_RETURN formats)
		// output count: one byte up to 252 outputs, three bytes past that (the
		// largest class holds several hundred); counted at three so the coinbase
		// never exceeds what datum_stratum_coinbase_fit_to_template allowed.
		//
		// total static bytes = 47+9+1+41+4+3+4+15 = 124 bytes
		// not-static bytes = pool_addr_script_len + cb_input_sz + (space_for_en_in_coinbase?0:10)
		//     --- it costs 10 extra bytes to do the OP_RETURN based extranonce
		//
		// This was 119, three bytes under the transaction with a one-byte output
		// count and five under it with a three-byte count; a coinbase built to a
		// template's room then exceeded the block's weight limit by up to 20
		// weight units.
		
		if (!space_for_en_in_coinbase) {
			cb_req_sz[1] = cb_req_sz[2] = cb_req_sz[3] = cb_req_sz[4] = cb_req_sz[5] = 124 + s->pool_addr_script_len + cb_input_sz + 10;
		} else {
			cb_req_sz[1] = cb_req_sz[2] = cb_req_sz[3] = cb_req_sz[4] = cb_req_sz[5] = 124 + s->pool_addr_script_len + cb_input_sz;
			cb_req_sz[2] += 10; // always OP_RETURN extranonce for type 2
		}
		
		// TYPE 1 - "Nicehash" friendly, max 500 bytes
		i = datum_stratum_coinbase_fit_to_template(500, cb_req_sz[1], s);
		generate_coinbase_txns_for_stratum_job_subtypebysize(s, 1, i, space_for_en_in_coinbase, cb1idx, cb2idx, false);
		
		// TYPE 3 - "Whatsminer" friendly, max 6500 bytes
		i = datum_stratum_coinbase_fit_to_template(6500, cb_req_sz[3], s);
		generate_coinbase_txns_for_stratum_job_subtypebysize(s, 3, i, space_for_en_in_coinbase, cb1idx, cb2idx, false);
		
		// TYPE 4 - "YUGE", max 16KB
		i = datum_stratum_coinbase_fit_to_template(16000, cb_req_sz[4], s);
		generate_coinbase_txns_for_stratum_job_subtypebysize(s, 4, i, space_for_en_in_coinbase, cb1idx, cb2idx, false);
		
		// TYPE 5 - "Antminer 2", max 2250 bytes
		i = datum_stratum_coinbase_fit_to_template(2250, cb_req_sz[5], s);
		generate_coinbase_txns_for_stratum_job_subtypebysize(s, 5, i, space_for_en_in_coinbase, cb1idx, cb2idx, false);
		
		// TYPE 2 - Older Antminer stock (S19)
		i = datum_stratum_coinbase_fit_to_template(755, cb_req_sz[2], s);
		generate_coinbase_txns_for_stratum_job_subtypebysize(s, 2, i, false, cb1idx, cb2idx, true);
	}
	
	// prep binary versions of the coinbase for speeding up later
	for(k=0;k<MAX_COINBASE_TYPES;k++) {
		i = strlen(s->coinbase[k].coinb1);
		s->coinbase[k].coinb1_len = 0;
		for(j=0;j<i;j+=2) {
			s->coinbase[k].coinb1_bin[j>>1] = hex2bin_uchar(&s->coinbase[k].coinb1[j]);
			s->coinbase[k].coinb1_len++;
		}
		i = strlen(s->coinbase[k].coinb2);
		s->coinbase[k].coinb2_len = 0;
		for(j=0;j<i;j+=2) {
			s->coinbase[k].coinb2_bin[j>>1] = hex2bin_uchar(&s->coinbase[k].coinb2[j]);
			s->coinbase[k].coinb2_len++;
		}
	}
	
	if (empty_only) {
		i = strlen(s->subsidy_only_coinbase.coinb1);
		s->subsidy_only_coinbase.coinb1_len = 0;
		for(j=0;j<i;j+=2) {
			s->subsidy_only_coinbase.coinb1_bin[j>>1] = hex2bin_uchar(&s->subsidy_only_coinbase.coinb1[j]);
			s->subsidy_only_coinbase.coinb1_len++;
		}
		i = strlen(s->subsidy_only_coinbase.coinb2);
		s->subsidy_only_coinbase.coinb2_len = 0;
		for(j=0;j<i;j+=2) {
			s->subsidy_only_coinbase.coinb2_bin[j>>1] = hex2bin_uchar(&s->subsidy_only_coinbase.coinb2[j]);
			s->subsidy_only_coinbase.coinb2_len++;
		}
	}

	datum_stratum_job_refresh_blake2b(s);
	return true;
}

void generate_coinbase_txns_for_stratum_job(T_DATUM_STRATUM_JOB *s, bool empty_only) {
	(void)generate_coinbase_txns_for_stratum_job_ex(s, empty_only, NULL);
}

bool generate_coinbase_txns_for_stratum_job_pooled(T_DATUM_STRATUM_JOB *s, const T_DATUM_POOLED_SETTLEMENT *settle) {
	if (!settle) return false;
	return generate_coinbase_txns_for_stratum_job_ex(s, false, settle);
}

int datum_coinbaser_v2_parse(T_DATUM_STRATUM_JOB *s, unsigned char *coinbaser, int cblen, bool must_free) {
	// Parse the pool's raw coinbaser (coinbaser ID byte, then outputs of value u64le, script
	// length u8, script) into detached storage, and copy it into the job only if the WHOLE
	// reply is well formed. Returns the number of payout outputs (>= 0), or -1 with the job's
	// outputs, count and coinbaser ID untouched when the reply is rejected: truncated, a bad
	// script length, an output that would take the total past the job's coinbase value
	// (overflow-safe), more than DATUM_COINBASER_MAX_OUTPUTS outputs, or bytes left over.
	// AlphaPool release 3: a reply is used whole or not at all. Upstream stopped at an
	// over-value output and at output 512 and returned the count parsed up to there; such
	// replies are now rejected. Malformed replies (truncation, bad script length) used to
	// return 0 with the count cleared; they now return -1, which callers treat the same way.
	T_DATUM_TXN_OUTPUT *outs = NULL;
	uint64_t outval = 0;
	uint64_t tally = 0;
	int cidx = 0;
	int slen = 0;
	int cbvalid = 0;
	int datum_id;
	int result = -1;
	
	if (!coinbaser || cblen < 1) {
		DLOG_WARN("Coinbaser is empty; rejecting it");
		return -1;
	}
	
	DLOG_DEBUG("Coinbaser v2 size %d", cblen);
	
	datum_id = coinbaser[cidx]; cidx++;
	
	if (cidx == cblen) {
		// the coinbaser ID alone: a reply that carries no payout outputs (upstream: 0, count cleared)
		s->available_coinbase_outputs_count = 0;
		result = 0;
		goto done;
	}
	
	outs = calloc(DATUM_COINBASER_MAX_OUTPUTS, sizeof(*outs));
	if (!outs) {
		DLOG_ERROR("Could not allocate memory to parse a coinbaser; rejecting it");
		goto done;
	}
	
	while (cidx < cblen) {
		if (cbvalid >= DATUM_COINBASER_MAX_OUTPUTS) {
			DLOG_ERROR("Coinbaser carries more than %d outputs; rejecting all of it", DATUM_COINBASER_MAX_OUTPUTS);
			goto done;
		}
		if ((cblen - cidx) < (8 + 1)) {
			DLOG_ERROR("Coinbaser length is invalid (%d byte(s) left over after output %d); rejecting all of it", cblen - cidx, cbvalid);
			goto done;
		}
		outval = upk_u64le(coinbaser, cidx); cidx+=8;
		// tally never exceeds the coinbase value, so this cannot wrap (the old tally + outval could)
		if (outval > (s->coinbase_value - tally)) {
			DLOG_ERROR("Coinbaser output %d (%"PRIu64" sats) takes the total past the job's coinbase value (%"PRIu64" of %"PRIu64" sats already assigned); rejecting all of it", cbvalid, outval, tally, s->coinbase_value);
			goto done;
		}
		slen = coinbaser[cidx]; cidx++;
		if (slen < 2 || slen > 64 || slen > (cblen - cidx)) {
			DLOG_ERROR("Script length (%d) of coinbaser output %d is invalid; rejecting all of it", slen, cbvalid);
			goto done;
		}
		
		tally += outval;
		memcpy(outs[cbvalid].output_script, &coinbaser[cidx], slen); cidx+=slen;
		// 64-bit value in sats is part of the output
		outs[cbvalid].value_sats = outval;
		if (outs[cbvalid].output_script[0] == 0x76) { // kludge for checking for P2PKH output
			outs[cbvalid].sigops = 4;
		} else {
			outs[cbvalid].sigops = 0;
		}
		
		outs[cbvalid].output_script_len = slen;
		
		cbvalid++;
	}
	
	// the whole reply is good: now, and only now, the job gets it
	memcpy(s->available_coinbase_outputs, outs, (size_t)cbvalid * sizeof(*outs));
	s->datum_coinbaser_id = datum_id;
	s->available_coinbase_outputs_count = cbvalid;
	result = cbvalid;
	
done:
	free(outs);
	if (must_free) free(coinbaser);
	return result;
}

// Reads a Bitcoin CompactSize at tx[*pos], advancing *pos. False if it runs past len.
static bool datum_cb_read_varint(const unsigned char *tx, size_t len, size_t *pos, uint64_t *out) {
	size_t n, i;
	uint64_t v = 0;
	unsigned char b;
	
	if (*pos >= len) return false;
	b = tx[*pos]; (*pos)++;
	if (b < 0xfd) {
		*out = b;
		return true;
	}
	n = (b == 0xfd) ? 2 : ((b == 0xfe) ? 4 : 8);
	if ((len - *pos) < n) return false;
	for (i = 0; i < n; i++) {
		v |= ((uint64_t)tx[*pos + i]) << (8 * i);
	}
	*pos += n;
	*out = v;
	return true;
}

const char *datum_coinbaser_check_reason(int code) {
	switch (code) {
		case DATUM_CB_CHECK_OK: return "ok";
		case DATUM_CB_CHECK_NO_ASSIGNMENT: return "no assignment or pool script to check against";
		case DATUM_CB_CHECK_MALFORMED: return "coinbase does not decode as one transaction";
		case DATUM_CB_CHECK_MISSING_OUTPUT: return "an assigned output is missing (truncated coinbase?)";
		case DATUM_CB_CHECK_EXTRA_OUTPUT: return "an output that is not in the assignment";
		case DATUM_CB_CHECK_NONZERO_OP_RETURN: return "an OP_RETURN output carries value";
		case DATUM_CB_CHECK_POOL_AMOUNT: return "pool output is not exactly the unassigned remainder";
		case DATUM_CB_CHECK_TOTAL: return "outputs do not add up to the coinbase value";
		default: return "unknown";
	}
}

// Pooled-only publication check (AlphaPool release 3). Decodes the coinbase
// class a miner is actually served — coinb1, the 12 zero bytes the submit path puts where the
// extranonce goes (on BLAKE2b the hasher's extranonce lives in the header), coinb2, with the
// PoT placeholder byte set — as one transaction, and requires of its outputs:
//   - every assignment output (script bytes + value, from s->available_coinbase_outputs[])
//     is present, with exact multiplicity;
//   - the only other output with value is the settlement's pool script, receiving exactly
//     coinbase_value - sum(assignment), and it is present iff that remainder is > 0 (when the
//     assignment covers the whole coinbase value there is none,
//     and the builder writes a zero-value OP_RETURN "dead" output in its place);
//   - every remaining output is a zero-value OP_RETURN (witness commitment, extranonce
//     OP_RETURN when the extranonce does not fit in the coinbase input, the dead output);
//   - the outputs add up to exactly s->coinbase_value.
// Returns DATUM_CB_CHECK_OK or the first reason found.
int datum_coinbaser_pooled_coinbase_check(const T_DATUM_STRATUM_JOB *s, int coinbase_index, const T_DATUM_POOLED_SETTLEMENT *settle) {
	unsigned char tx[MAX_COINBASE_TXN_SIZE_BYTES];
	bool used[DATUM_COINBASER_MAX_OUTPUTS];
	const T_DATUM_STRATUM_COINBASE *cb;
	uint64_t v, n_in, n_out, script_len, value, total = 0, assigned = 0, remainder, pool_value = 0;
	size_t len, pos = 0, o, a;
	const unsigned char *script;
	const int n_assigned = s ? s->available_coinbase_outputs_count : 0;
	bool matched, pool_seen = false;
	
	if (!s || !settle || (coinbase_index < 0) || (coinbase_index >= MAX_COINBASE_TYPES)) return DATUM_CB_CHECK_NO_ASSIGNMENT;
	if ((n_assigned <= 0) || (n_assigned > DATUM_COINBASER_MAX_OUTPUTS)) return DATUM_CB_CHECK_NO_ASSIGNMENT;
	if ((settle->pool_script_len <= 0) || (settle->pool_script_len > MAX_OUTPUT_SCRIPT_LEN)) return DATUM_CB_CHECK_NO_ASSIGNMENT;
	
	for (a = 0; a < (size_t)n_assigned; a++) {
		if (s->available_coinbase_outputs[a].value_sats > (UINT64_MAX - assigned)) return DATUM_CB_CHECK_TOTAL;
		assigned += s->available_coinbase_outputs[a].value_sats;
	}
	if (assigned > s->coinbase_value) return DATUM_CB_CHECK_TOTAL;
	remainder = s->coinbase_value - assigned;
	
	// the transaction exactly as the miner/submit path assembles it
	cb = &s->coinbase[coinbase_index];
	if ((cb->coinb1_len < 1) || (cb->coinb2_len < 0)) return DATUM_CB_CHECK_MALFORMED;
	len = (size_t)cb->coinb1_len + 12 + (size_t)cb->coinb2_len;
	if (len > sizeof(tx)) return DATUM_CB_CHECK_MALFORMED;
	memcpy(tx, cb->coinb1_bin, cb->coinb1_len);
	memset(tx + cb->coinb1_len, 0, 12);
	memcpy(tx + cb->coinb1_len + 12, cb->coinb2_bin, cb->coinb2_len);
	if ((s->target_pot_index >= 0) && (s->target_pot_index < cb->coinb1_len)) {
		tx[s->target_pot_index] = 0xFF;
	}
	
	// version, one input (outpoint, script, sequence)
	if (len < 4) return DATUM_CB_CHECK_MALFORMED;
	pos = 4;
	if (!datum_cb_read_varint(tx, len, &pos, &n_in) || (n_in != 1)) return DATUM_CB_CHECK_MALFORMED;
	if ((len - pos) < 36) return DATUM_CB_CHECK_MALFORMED;
	pos += 36;
	if (!datum_cb_read_varint(tx, len, &pos, &script_len) || (script_len > (len - pos))) return DATUM_CB_CHECK_MALFORMED;
	pos += (size_t)script_len;
	if ((len - pos) < 4) return DATUM_CB_CHECK_MALFORMED;
	pos += 4;
	
	// outputs
	if (!datum_cb_read_varint(tx, len, &pos, &n_out) || (n_out < 1) || (n_out > ((len - pos) / 9))) return DATUM_CB_CHECK_MALFORMED;
	memset(used, 0, sizeof(used));
	for (o = 0; o < (size_t)n_out; o++) {
		if ((len - pos) < 8) return DATUM_CB_CHECK_MALFORMED;
		value = upk_u64le(tx, (int)pos); pos += 8;
		if (!datum_cb_read_varint(tx, len, &pos, &v) || (v > (len - pos))) return DATUM_CB_CHECK_MALFORMED;
		script = &tx[pos];
		script_len = v;
		pos += (size_t)v;
		
		if (value > (UINT64_MAX - total)) return DATUM_CB_CHECK_TOTAL;
		total += value;
		
		// an assignment output not yet matched?
		matched = false;
		for (a = 0; a < (size_t)n_assigned; a++) {
			if (used[a]) continue;
			if (s->available_coinbase_outputs[a].value_sats != value) continue;
			if ((uint64_t)s->available_coinbase_outputs[a].output_script_len != script_len) continue;
			if (memcmp(s->available_coinbase_outputs[a].output_script, script, (size_t)script_len)) continue;
			used[a] = true;
			matched = true;
			break;
		}
		if (matched) continue;
		
		// the pool's remainder output?
		if ((value > 0) && (script_len == (uint64_t)settle->pool_script_len) && !memcmp(script, settle->pool_script, (size_t)script_len)) {
			if (pool_seen) return DATUM_CB_CHECK_POOL_AMOUNT;
			pool_seen = true;
			pool_value = value;
			continue;
		}
		
		// anything else must be an OP_RETURN, and carry nothing
		if ((script_len >= 1) && (script[0] == 0x6a)) {
			if (value != 0) return DATUM_CB_CHECK_NONZERO_OP_RETURN;
			continue;
		}
		return DATUM_CB_CHECK_EXTRA_OUTPUT;
	}
	
	// lock time, and nothing after it
	if ((len - pos) != 4) return DATUM_CB_CHECK_MALFORMED;
	
	for (a = 0; a < (size_t)n_assigned; a++) {
		if (!used[a]) return DATUM_CB_CHECK_MISSING_OUTPUT;
	}
	if (remainder > 0) {
		if (!pool_seen || (pool_value != remainder)) return DATUM_CB_CHECK_POOL_AMOUNT;
	} else if (pool_seen) {
		return DATUM_CB_CHECK_POOL_AMOUNT;
	}
	if (total != s->coinbase_value) return DATUM_CB_CHECK_TOTAL;
	
	return DATUM_CB_CHECK_OK;
}

// May the coinbaser thread build a coinbase WITHOUT the pool's coinbaser? Only
// solo mode may (that coinbase pays the miner's own address). Pooled-only never
// may: a local coinbase there is not built from the pool's payout assignment.
bool datum_coinbaser_local_fallback_allowed(bool protocol_active, bool pooled_only) {
	if (protocol_active) return false;   // the pool's coinbaser is the only source
	return !pooled_only;
}

// What the coinbaser thread may build from a fetch result. `fetched` is
// datum_protocol_coinbaser_fetch()'s answer: >0 payout outputs parsed, 0 = a
// reply carrying none, -1 = no usable reply (link down, send failed, timeout,
// wait error). Returns the output count to build with (>= 0), or -1 = keep the
// job waiting. Pooled-only builds ONLY from a reply with payout outputs: a
// coinbase built from anything else would not carry the pool's payout
// assignment. Solo keeps upstream's behaviour: mine on its own address.
int datum_coinbaser_outputs_decision(int fetched, bool pooled_only) {
	if (fetched > 0) return fetched;
	if (pooled_only) return -1;
	return 0;
}

// Marks job s published: miners may be sent it from now on. Pooled-only also ends the
// coinbaser outage, atomically with the flag (the tracker's lock nests inside the job's).
static bool datum_coinbaser_publish(T_DATUM_STRATUM_JOB *s, bool pooled_only) {
	if (!need_coinbaser_rwlocks_init_done) return false;
	pthread_rwlock_wrlock(&need_coinbaser_rwlocks[s->global_index]);
	s->need_coinbaser = false;
	if (pooled_only) datum_pooled_outage_note_published(s->job_seq);
	pthread_rwlock_unlock(&need_coinbaser_rwlocks[s->global_index]);
	return true;
}

// Pooled-only step (AlphaPool release 3). The coinbase that is
// published is built from a complete assignment only, with nothing taken from the live link
// state, checked output by output against that assignment, and published only while the DATUM
// session the assignment was requested on is still the active one. Anything else leaves
// need_coinbaser set: miners keep the work they have (the fail-close tracker drops them if
// this lasts) and the job is asked for again.
static int datum_coinbaser_pooled_step(T_DATUM_STRATUM_JOB *s, const T_DATUM_COINBASER_IO *io) {
	T_DATUM_POOLED_SETTLEMENT settle;
	uint64_t request_generation = 0;
	int fetched, check;
	
	if (!io->link_active(io->ctx)) {
		// no pool, no coinbase: pooled-only never builds one locally
		datum_pooled_outage_note_unready(s->job_seq, io->now_ms(io->ctx));
		return DATUM_COINBASER_STEP_WAIT;
	}
	
	// what the assignment will be bound to: the pool's remainder script as configured now
	// (the session is the one the request actually goes out on, reported by the fetch)
	memset(&settle, 0, sizeof(settle));
	settle.pool_script_len = datum_config.override_mining_pool_scriptpubkey_len;
	if ((settle.pool_script_len <= 0) || (settle.pool_script_len > MAX_OUTPUT_SCRIPT_LEN)) {
		datum_pooled_outage_note_unready(s->job_seq, io->now_ms(io->ctx));
		return DATUM_COINBASER_STEP_WAIT;
	}
	memcpy(settle.pool_script, datum_config.override_mining_pool_scriptpubkey, settle.pool_script_len);
	
	fetched = io->fetch(io->ctx, s, &request_generation);
	if (datum_coinbaser_outputs_decision(fetched, true) < 0) {
		// no usable reply (link down, send failure, timeout), a rejected reply, or a reply
		// without payout outputs: there is no payout assignment to build a coinbase from
		if ((fetched == 0) && !s->pooled_zero_outputs_logged) {
			s->pooled_zero_outputs_logged = true;
			DLOG_WARN("Pooled-only: the pool's coinbaser for job %d carried no payout outputs — not building a coinbase from it, retrying", s->global_index);
		}
		datum_pooled_outage_note_unready(s->job_seq, io->now_ms(io->ctx));
		// an empty or rejected reply comes back fast; do not hammer the pool
		return ((fetched == 0) || (fetched == DATUM_COINBASER_FETCH_REJECTED)) ? DATUM_COINBASER_STEP_BACKOFF : DATUM_COINBASER_STEP_WAIT;
	}
	settle.session_generation = request_generation;
	s->coinbaser_session_generation = request_generation;
	
	DLOG_DEBUG("Generating coinbases for %d assigned outputs (session %"PRIu64")", fetched, request_generation);
	if (!generate_coinbase_txns_for_stratum_job_pooled(s, &settle)) {
		datum_pooled_outage_note_unready(s->job_seq, io->now_ms(io->ctx));
		return DATUM_COINBASER_STEP_BACKOFF;
	}
	
	// the key guard: the class miners are served must pay exactly this assignment
	check = datum_coinbaser_pooled_coinbase_check(s, COINBASE_TYPE_YUGE, &settle);
	if (check != DATUM_CB_CHECK_OK) {
		if (!s->pooled_withheld_logged) {
			s->pooled_withheld_logged = true;
			DLOG_ERROR("Pooled-only: WITHHOLDING job %d — its coinbase fails the publication check: %s (%d assigned output(s), coinbase value %"PRIu64" sats). Not serving it; asking the pool again.",
				s->global_index, datum_coinbaser_check_reason(check), s->available_coinbase_outputs_count, s->coinbase_value);
		}
		datum_pooled_outage_note_unready(s->job_seq, io->now_ms(io->ctx));
		return DATUM_COINBASER_STEP_BACKOFF;
	}
	
	// The assignment belongs to the session it was requested on: if that session ended (link
	// down, or a reconnect started a new generation) or the pool changed its payout script
	// meanwhile, it is stale. Nothing built above has reached a miner; discard and ask again.
	if ((!request_generation) || (!io->link_active(io->ctx)) || (io->session_generation(io->ctx) != request_generation) ||
	    (datum_config.override_mining_pool_scriptpubkey_len != settle.pool_script_len) ||
	    memcmp(datum_config.override_mining_pool_scriptpubkey, settle.pool_script, settle.pool_script_len)) {
		if (!s->pooled_stale_logged) {
			s->pooled_stale_logged = true;
			DLOG_WARN("Pooled-only: discarding job %d's coinbaser — DATUM session %"PRIu64" it was requested on is no longer active; asking again", s->global_index, request_generation);
		}
		datum_pooled_outage_note_unready(s->job_seq, io->now_ms(io->ctx));
		return DATUM_COINBASER_STEP_WAIT;
	}
	
	if (!datum_coinbaser_publish(s, true)) {
		datum_pooled_outage_note_unready(s->job_seq, io->now_ms(io->ctx));
		return DATUM_COINBASER_STEP_WAIT;
	}
	DLOG_DEBUG("Generated, checked and notified (job %d, %d outputs, session %"PRIu64").", s->global_index, fetched, request_generation);
	return DATUM_COINBASER_STEP_PUBLISHED;
}

int datum_coinbaser_job_step(T_DATUM_STRATUM_JOB *s, const T_DATUM_COINBASER_IO *io) {
	uint64_t request_generation = 0;
	
	if (!s || !io) return DATUM_COINBASER_STEP_WAIT;
	if (datum_config.datum_pooled_mining_only) {
		return datum_coinbaser_pooled_step(s, io);
	}
	
	// Not pooled-only: upstream's behaviour, unchanged. With the link down or no usable reply
	// the job is built without the pool's payout outputs, exactly as upstream builds it,
	// and published.
	const bool link_active = io->link_active(io->ctx);
	const int fetched = link_active ? io->fetch(io->ctx, s, &request_generation) : -1;
	const int i = datum_coinbaser_outputs_decision(fetched, false);
	if (fetched <= 0) s->available_coinbase_outputs_count = 0; // solo: our own address only
	DLOG_DEBUG("Generating coinbases for up to %d outputs", i);
	generate_coinbase_txns_for_stratum_job(s, false);
	if (!datum_coinbaser_publish(s, false)) return DATUM_COINBASER_STEP_WAIT;
	DLOG_DEBUG("Generated and notified.");
	return DATUM_COINBASER_STEP_PUBLISHED;
}

static int datum_coinbaser_io_fetch(void *ctx, T_DATUM_STRATUM_JOB *s, uint64_t *request_generation) {
	(void)ctx;
	return datum_protocol_coinbaser_fetch_ex(s, request_generation);
}

static bool datum_coinbaser_io_link_active(void *ctx) {
	(void)ctx;
	return datum_protocol_is_active();
}

static uint64_t datum_coinbaser_io_session_generation(void *ctx) {
	(void)ctx;
	return datum_protocol_session_generation();
}

static uint64_t datum_coinbaser_io_now_ms(void *ctx) {
	(void)ctx;
	return monotonic_time_millis();
}

void *datum_coinbaser_thread(void *ptr) {
	int sjob = -1;
	T_DATUM_STRATUM_JOB *s = NULL;
	bool need_coinbaser = false;
	int r;
	const T_DATUM_COINBASER_IO io = {
		.fetch = datum_coinbaser_io_fetch,
		.link_active = datum_coinbaser_io_link_active,
		.session_generation = datum_coinbaser_io_session_generation,
		.now_ms = datum_coinbaser_io_now_ms,
		.ctx = NULL,
	};
	
	DLOG_DEBUG("Coinbaser thread active");
	
	while(1) {
		// check if we need to fetch any new coinbasers
		// check if the stratum job has been updated
		pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
		if (global_latest_stratum_job_index != sjob) {
			s = global_cur_stratum_jobs[global_latest_stratum_job_index];
			if (s) {
				sjob = global_latest_stratum_job_index;
				if (s->need_coinbaser) {
					need_coinbaser = true;
				}
			} else {
				need_coinbaser = false;
			}
		}
		pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
		
		if (need_coinbaser) {
			// fetch remote coinbaser for job
			DLOG_DEBUG("Job %d needs a coinbaser!", sjob);
			// AlphaPool release 3: pooled-only never publishes
			// a coinbase without the pool's complete payout assignment — see
			// datum_coinbaser_pooled_step(). Until one is published the job stays waiting
			// (the stratum side keeps miners on their last work and fails closed) and this
			// loop asks again. Solo keeps upstream's behaviour.
			r = datum_coinbaser_job_step(s, &io);
			if (r == DATUM_COINBASER_STEP_PUBLISHED) {
				need_coinbaser = false;
			} else if (r == DATUM_COINBASER_STEP_BACKOFF) {
				usleep(250000);
			}
		}
		
		usleep(12000);
	}
}

int datum_coinbaser_init(void) {
	pthread_t pthread_datum_coinbaser_thread;
	int result = pthread_create(&pthread_datum_coinbaser_thread, NULL, datum_coinbaser_thread, NULL);

	if (result != 0) {
		DLOG_FATAL("datum_coinbaser_init: pthread_create failed with code %d", result);
		return -1;
	}

	return 0;
}
