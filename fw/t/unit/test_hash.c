/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/bug.h>

#include "str.h"
#include "hash.h"
#include "test.h"

#include "hash.c"

/* NOTE: hashing is a probabilistic thing. Some tests may give false results. */

TEST(tfw_hash_str, calcs_diff_hash_for_diff_str)
{
	/* Note: collisions are possible.
	 * The hashes should be different with high probability,
	 * but at this point we are not going to write some statistical tests.
	 */
	TfwStr s1 = { .len = 10, .data = (void *)"foobarbaz1" };
	TfwStr s2 = { .len = 10, .data = (void *)"Foobarbaz1" };
	TfwStr s3 = { .len = 10, .data = (void *)"foobarbaz2" };
	TfwStr s4 = { .len = 9, .data = (void *)"foobarbaz" };
	TfwStr s5 = { .len = 11, .data = (void *)"foobarbaz11" };
	TfwStr s6 = { .len = 0, .data = (void *)"" };

	unsigned long h[] = {
		tfw_hash_str(&s1),
		tfw_hash_str(&s2),
		tfw_hash_str(&s3),
		tfw_hash_str(&s4),
		tfw_hash_str(&s5),
		tfw_hash_str(&s6),
	};

	int i, j;
	for (i = 0; i < ARRAY_SIZE(h); ++i) {
		for (j = 0; j < ARRAY_SIZE(h); ++j) {
			if (i != j && h[i] == h[j])
				TEST_FAIL("Equal hashes: h[%d] => %#lx,  "
				          "[%d] => %#lx", i, h[i], j, h[j]);
		}
	}
}

TEST(tfw_hash_str, calcs_same_hash_for_diff_chunks_n)
{
	const char data_const[] = "The quick brown fox jumps over the lazy dog";
	size_t len = sizeof(data_const) - 1;
	char *data = (char *)data_const;
	TfwStr s_single_piece = {.data = data, .len = len};
	int a1, a2;
	unsigned long hash_fast_expected = tfw_hash_str(&s_single_piece);
	unsigned long hash_fast;
	unsigned int hash_crc32_expected = tfw_str_crc32_calc(&s_single_piece);
	unsigned int hash_crc32;

	/* Iterate over all possible splits by two points. */
	for (a1 = 0; a1 < len; a1++) {
		for (a2 = a1; a2 < len; a2++) {
			TfwStr s = {
				.chunks = (TfwStr[]){
					{.data = data,      .len = a1 - 0},
					{.data = data + a1, .len = a2 - a1},
					{.data = data + a2, .len = len - a2},
				},
				.nchunks = 3,
				.len = len,
			};

			EXPECT_EQ(s.chunks[0].len + s.chunks[1].len +
				  s.chunks[2].len, len);

			hash_fast = tfw_hash_str(&s);
			EXPECT_EQ(hash_fast, hash_fast_expected);
			if (hash_fast != hash_fast_expected)
				return;

			hash_crc32 = tfw_str_crc32_calc(&s);
			EXPECT_EQ(hash_crc32, hash_crc32_expected);
			if (hash_crc32 != hash_crc32_expected)
				return;
		}
	}
}

TEST(tfw_hash_str, hashes_all_chars)
{
	int i;
	unsigned long h1, h2;
	char buf1[256] = { 0 };
	char buf2[256] = { 0 };
	TfwStr s1 = { .len = 0,	.data = buf1 };
	TfwStr s2 = { .len = 0, .data = buf2 };

	/* Change of each individual byte in the string should change
	 * the hash value. */
	for (i = 0; i < 255; ++i) {
		s1.len = s2.len = (i + 1);
		buf1[i] = 'a';
		buf2[i] = 'b';

		h1 = tfw_hash_str(&s1);
		h2 = tfw_hash_str(&s2);
		if (h1 == h2)
			TEST_FAIL("Equal hashes (%#lx) for different strings:\n"
			          " s1: %.*s (len %lu)\n"
			          " s2: %.*s (len %lu)",
			          h1,
			          PR_TFW_STR(&s1), s1.len,
			          PR_TFW_STR(&s2), s2.len);

		buf2[i] = 'a';
		h2 = tfw_hash_str(&s2);
		if (h1 != h2)
			TEST_FAIL("Different hashes for equal strings:\n"
			          " s1: %#08lx: %.*s (len %lu)\n"
			          " s2: %#08lx: %.*s (len %lu)",
			          h1, PR_TFW_STR(&s1), s1.len,
			          h2, PR_TFW_STR(&s2), s2.len);
	}
}

TEST(tfw_hash_str, doesnt_read_behind_end_of_buf)
{
	char buf[256] = { 0 };
	TfwStr s = {
		.len = 0,
		.data = buf
	};

	unsigned long h1, h2;
	int i;

	for (i = 0; i < 255; ++i) {
		s.len = i;

		buf[i] = 'x';
		h1 = tfw_hash_str(&s);

		memset(&buf[i + 1], i, (sizeof(buf) - i - 1));
		h2 = tfw_hash_str(&s);

		EXPECT_EQ(h1, h2);
	}
}

TEST(tfw_hash_str, distributes_all_input_across_hash_bits)
{
	char buf[31]; /* maximum tail */
	TfwStr str = {
		.data = buf,
		.len = sizeof(buf)
	};

	unsigned long h1, h2;
	int i;

	memset(buf, 'a', sizeof(buf));
	h1 = tfw_hash_str(&str);

	/*
	 * For a good hash function, a change of a single bit in the input will
	 * cause changing many bits in the output (with high probability).
	 * Our hash function calculates high and low halves of 64-bit output
	 * key, so we change two bits simultaneously in the test.
	 * Probably, this is good to fix.
	 */
	for (i = 0; i < sizeof(buf) / 2; ++i) {
		buf[i] = buf[i + 8] = 'b';
		h2 = tfw_hash_str(&str);
		buf[i] = buf[i + 8] = 'a';

		EXPECT_NE(h1 & 0x00000000000000FF, h2 & 0x00000000000000FF);
		EXPECT_NE(h1 & 0x000000000000FF00, h2 & 0x000000000000FF00);
		EXPECT_NE(h1 & 0x0000000000FF0000, h2 & 0x0000000000FF0000);
		EXPECT_NE(h1 & 0x00000000FF000000, h2 & 0x00000000FF000000);
		EXPECT_NE(h1 & 0x000000FF00000000, h2 & 0x000000FF00000000);
		EXPECT_NE(h1 & 0x0000FF0000000000, h2 & 0x0000FF0000000000);
		EXPECT_NE(h1 & 0x00FF000000000000, h2 & 0x00FF000000000000);
		EXPECT_NE(h1 & 0xFF00000000000000, h2 & 0xFF00000000000000);
	}
}

TEST_SUITE(hash)
{
	TEST_RUN(tfw_hash_str, calcs_diff_hash_for_diff_str);
	TEST_RUN(tfw_hash_str, calcs_same_hash_for_diff_chunks_n);
	TEST_RUN(tfw_hash_str, hashes_all_chars);
	TEST_RUN(tfw_hash_str, doesnt_read_behind_end_of_buf);
	TEST_RUN(tfw_hash_str, distributes_all_input_across_hash_bits);
}
