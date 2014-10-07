/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

#include "test.h"
#include "../str.h"


static const TfwStr chunks[] = {
	{ .flags = 0, .len = 0, .ptr = "" },
	{ .flags = 0, .len = 3, .ptr = "foo" },
	{ .flags = 0, .len = 6, .ptr = "barbaz" }
};

static const TfwStr compound_str = {
	.flags = TFW_STR_COMPOUND,
	.len = 3,
	.ptr = (void *)chunks
};


TEST(tfw_str_len, summarizes_chunk_lenghs)
{
	int len = tfw_str_len(&compound_str);

	EXPECT_EQ(9, len);
}

TEST(tfw_str_to_cstr, copies_all_chunks)
{
	char buf[16] = { 0xA0 };
	int copied_len;
	const char *expected_str = "foobarbaz";

	copied_len = tfw_str_to_cstr(&compound_str, buf, sizeof(buf));

	EXPECT_EQ(9, copied_len);
	EXPECT_EQ(0, strcmp(expected_str, buf));
}

TEST(tfw_str_to_cstr, limits_and_terminates_output)
{
	char buf[6] = { 0xAA };
	int copied_len;
	const char *expected_str = "fooba";

	copied_len = tfw_str_to_cstr(&compound_str, buf, sizeof(buf));

	EXPECT_EQ(sizeof(buf) - 1, copied_len);
	EXPECT_EQ(buf[copied_len], '\0');
	EXPECT_EQ(0, strcmp(expected_str, buf));
}

TEST(tfw_str_eq_cstr, compares_compound_str)
{
	const TfwStr *str = &compound_str;
	const char *right = "foobarbaz";
	const char *wrong1 = "";
	const char *wrong2 = "foo";
	const char *wrong3 = "foobarbar";
	const char *wrong4 = "foobarbaz1";
	size_t right_len = strlen(right);
	size_t wrong1_len = strlen(wrong1);
	size_t wrong2_len = strlen(wrong2);
	size_t wrong3_len = strlen(wrong3);
	size_t wrong4_len = strlen(wrong4);

	EXPECT_TRUE(tfw_str_eq_cstr(str, right, right_len));
	EXPECT_FALSE(tfw_str_eq_cstr(str, wrong1, wrong1_len));
	EXPECT_FALSE(tfw_str_eq_cstr(str, wrong2, wrong2_len));
	EXPECT_FALSE(tfw_str_eq_cstr(str, wrong3, wrong3_len));
	EXPECT_FALSE(tfw_str_eq_cstr(str, wrong4, wrong4_len));
}

TEST(tfw_str_eq_cstr_ci, compares_compound_str_ignoring_case)
{
	const TfwStr *str = &compound_str;
	const char *right1 = "foobarbaz";
	const char *right2 = "fooBarbAz";
	const char *wrong1 = "foobar";
	const char *wrong2 = "fooBarbaz!";
	size_t right1_len = strlen(right1);
	size_t right2_len = strlen(right2);
	size_t wrong1_len = strlen(wrong1);
	size_t wrong2_len = strlen(wrong2);

	EXPECT_TRUE(tfw_str_eq_cstr_ci(str, right1, right1_len));
	EXPECT_TRUE(tfw_str_eq_cstr_ci(str, right2, right2_len));
	EXPECT_FALSE(tfw_str_eq_cstr_ci(str, wrong1, wrong1_len));
	EXPECT_FALSE(tfw_str_eq_cstr_ci(str, wrong2, wrong2_len));
}

TEST(tfw_str_startswith_cstr_ci, tests_compound_str_prefix_ignoring_case)
{
	const TfwStr *str = &compound_str;
	const char *right1 = "f";
	const char *right2 = "fOObaR";
	const char *wrong1 = "fOO bar";
	const char *wrong2 = "foobarbazz";
	size_t right1_len = strlen(right1);
	size_t right2_len = strlen(right2);
	size_t wrong1_len = strlen(wrong1);
	size_t wrong2_len = strlen(wrong2);

	EXPECT_TRUE(tfw_str_startswith_cstr_ci(str, right1, right1_len));
	EXPECT_TRUE(tfw_str_startswith_cstr_ci(str, right2, right2_len));
	EXPECT_FALSE(tfw_str_startswith_cstr_ci(str, wrong1, wrong1_len));
	EXPECT_FALSE(tfw_str_startswith_cstr_ci(str, wrong2, wrong2_len));
}

TEST(tfw_str_startswith_cstr_ci, returns_true_if_prefix_is_empty_or_eq)
{
	/* Few corner cases here:
	 *  - Any string starts with itself.
	 *  - Any string starts with an empty string.
	 *  - An empty string starts with itself.
	 */
	const TfwStr str = {
		.flags = 0,
		.len = 4,
		.ptr = "abcd"
	};
	const TfwStr empty_str = {
		.flags = 0,
		.len = 0,
		.ptr = ""
	};
	const char *cstr = "abcd";
	const char *cstr2 = "aBCd";
	const char *empty_cstr = "";

	EXPECT_TRUE(tfw_str_startswith_cstr_ci(&str, cstr, 4));
	EXPECT_TRUE(tfw_str_startswith_cstr_ci(&str, cstr2, 4));
	EXPECT_TRUE(tfw_str_startswith_cstr_ci(&str, empty_cstr, 0));
	EXPECT_TRUE(tfw_str_startswith_cstr_ci(&empty_str, empty_cstr, 0));
}

TEST_SUITE(tfw_str)
{
	RUN_TEST(tfw_str_len, summarizes_chunk_lenghs);
	RUN_TEST(tfw_str_to_cstr, copies_all_chunks);
	RUN_TEST(tfw_str_to_cstr, limits_and_terminates_output);
	RUN_TEST(tfw_str_eq_cstr, compares_compound_str);
	RUN_TEST(tfw_str_eq_cstr_ci, compares_compound_str_ignoring_case);
	RUN_TEST(tfw_str_startswith_cstr_ci, tests_compound_str_prefix_ignoring_case);
	RUN_TEST(tfw_str_startswith_cstr_ci, returns_true_if_prefix_is_empty_or_eq);
}
