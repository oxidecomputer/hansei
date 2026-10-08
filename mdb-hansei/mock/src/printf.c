/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

extern void mdbmock_output(const char *text, int is_warning);

static void
emit(int is_warning, const char *fmt, va_list ap)
{
	char *text = NULL;
	if (vasprintf(&text, fmt, ap) < 0)
		return;
	mdbmock_output(text, is_warning);
	free(text);
}

void
mdb_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	emit(0, fmt, ap);
	va_end(ap);
}

void
mdb_warn(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	emit(1, fmt, ap);
	va_end(ap);
}
