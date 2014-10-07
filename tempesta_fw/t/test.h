/**
 *		Tempesta FW
 *
 * A basic set of macros for writing unit tests that run in the kernel space.
 *
 * This is a bit awkward approach for unit testing, but it allows to start
 * writing tests quickly with minimal effort (spent for mocking the kernel API).
 * Later on we may decide to move them into user-space. These macros try to
 * imitate the GoogleTest API. That should facilitate the future migration.
 *
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
#ifndef __TFW_TEST_H__
#define __TFW_TEST_H__

int  test_run_all(void);
void test_register_failure(void);

typedef void (*test_fixture_fn_t)(void);

void test_set_setup_fn(test_fixture_fn_t fn);
void test_set_teardown_fn(test_fixture_fn_t fn);
void test_call_setup_fn(void);
void test_call_teardown_fn(void);

#define TEST_BANNER "tfw_test: "

#define TEST_LOG(...) printk(KERN_INFO TEST_BANNER __VA_ARGS__)
#define TEST_LOG_LF(...) 	\
do {				\
	TEST_LOG(__VA_ARGS__);	\
	printk("\n");		\
} while (0)

#define TEST_ERR(...) printk(KERN_ERR  TEST_BANNER __VA_ARGS__)
#define TEST_ERR_LF(...) 	\
do {				\
	TEST_ERR(__VA_ARGS__);	\
	printk("\n");		\
} while (0)


#define TEST(unit, assertion)  static void test__ ##unit ##__ ##assertion(void)
#define TEST_SUITE(name) void test_suite__##name(void)
#define TEST_SETUP(fn) test_set_setup_fn(fn)
#define TEST_TEARDOWN(fn) test_set_teardown_fn(fn)

#define TEST_RUN(unit, assertion) 			\
do { 							\
	TEST_LOG_LF("TEST_RUN(%s, %s)", #unit, #assertion); \
	test_call_setup_fn();				\
	test__ ##unit ##__ ##assertion(); 		\
	test_call_teardown_fn();			\
} while (0)

#define TEST_SUITE_RUN(name) 				\
do { 							\
	TEST_LOG_LF("TEST_SUITE_RUN(%s)", #name); 	\
	test_suite__##name(); 				\
	test_set_setup_fn(NULL);			\
	test_set_teardown_fn(NULL);			\
} while (0)

#define TEST_FAIL(...) 					\
do {							\
	TEST_ERR_LF("FAIL:");				\
	TEST_ERR_LF("  %s():%d", __func__, __LINE__);	\
	TEST_ERR_LF("  " __VA_ARGS__);			\
	test_register_failure();			\
} while (0)



#define __EXPECT_CMP(name, expr1, expr2, cmp_expr)	\
do {							\
	typeof(expr1) _val1 = (expr1);			\
	typeof(expr2) _val2 = (expr2);			\
	if (cmp_expr)					\
		break;					\
	TEST_FAIL("%s(%s, %s) => (%#lx, %#lx)", name, #expr1, #expr2, 	\
	          (unsigned long)_val1, (unsigned long)_val2);		\
} while (0)

#define EXPECT_EQ(expr1, expr2) \
	__EXPECT_CMP("EXPECT_EQ", (expr1), (expr2), _val1 == _val2)

#define EXPECT_NE(expr1, expr2) \
	__EXPECT_CMP("EXPECT_NE", (expr1), (expr2), _val1 != _val2)

#define EXPECT_LT(expr1, expr2) \
	__EXPECT_CMP("EXPECT_LT", (expr1), (expr2), _val1 < _val2)

#define EXPECT_LE(expr1, expr2) \
	__EXPECT_CMP("EXPECT_LE", (expr1), (expr2), _val1 <= _val2)

#define EXPECT_GT(expr1, expr2) \
	__EXPECT_CMP("EXPECT_GT", (expr1), (expr2), _val1 > _val2)

#define EXPECT_GE(expr1, expr2) \
	__EXPECT_CMP("EXPECT_GE", (expr1), (expr2), _val1 >= val2)


#define __EXPECT_COND(name, expr, cond_expr)	\
do {						\
	typeof(expr) _val = (expr);		\
	if (cond_expr)				\
		break;				\
	TEST_FAIL("%s(%s) => %#lx", name, #expr, (unsigned long)_val); \
} while (0)

#define EXPECT_TRUE(expr) \
	__EXPECT_COND("EXPECT_TRUE", (expr), _val)

#define EXPECT_FALSE(expr) \
	__EXPECT_COND("EXPECT_FALSE", (expr), !_val)

#define EXPECT_NULL(expr) \
	__EXPECT_COND("EXPECT_NULL", (expr), _val == NULL)

#define EXPECT_NOT_NULL(expr) \
	__EXPECT_COND("EXPECT_NOT_NULL", (expr), _val != NULL)


#endif /* __TFW_TEST_H__ */
