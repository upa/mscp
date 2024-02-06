/* SPDX-License-Identifier: GPL-3.0-only */

#include <print.h>

/* message print functions */
static int __print_severity = MSCP_SEVERITY_WARN;

void set_print_severity(int serverity)
{
	if (serverity < 0)
		__print_severity = -1; /* no print */
	__print_severity = serverity;
}

int get_print_severity()
{
	return __print_severity;
}
