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

#include <linux/module.h>

#include "tempesta.h"
#include "test.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta FW tests");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");

static int __init
tfw_test_init(void)
{
	int fail_count = 0;

	printk("tfw_test: start\n");
	fail_count = run_all_tests();

	printk("tfw_test: finish - ");
	if (fail_count)
		printk("failed %d assertions\n", fail_count);
	else
		printk("all passed\n");

	return 0;
}

void
tfw_test_exit(void)
{
}

module_init(tfw_test_init);
module_exit(tfw_test_exit);
