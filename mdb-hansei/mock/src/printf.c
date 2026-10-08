/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void mdbmock_output(const char *text, int is_warning);

/*
 * mdb's own directives for bold, underline and reverse video, as an
 * ANSI terminal spells them (mdb renders them only on a terminal that
 * can; this host always does, for its tests to see).
 */
static char *
directives(const char *fmt)
{
	static const struct { const char *from, *to; } map[] = {
		{ "%<b>", "\033[1m" }, { "%</b>", "\033[0m" },
		{ "%<u>", "\033[4m" }, { "%</u>", "\033[0m" },
		{ "%<r>", "\033[7m" }, { "%</r>", "\033[0m" },
	};
	char *out = malloc(strlen(fmt) * 2 + 1), *o = out;
	while (*fmt != '\0') {
		size_t i, n = sizeof (map) / sizeof (map[0]);
		for (i = 0; i < n; i++) {
			size_t l = strlen(map[i].from);
			if (strncmp(fmt, map[i].from, l) == 0) {
				o = stpcpy(o, map[i].to);
				fmt += l;
				break;
			}
		}
		if (i == n)
			*o++ = *fmt++;
	}
	*o = '\0';
	return (out);
}

static void
emit(int is_warning, const char *fmt0, va_list ap)
{
	char *text = NULL;
	char *fmt = directives(fmt0);
	int rc = vasprintf(&text, fmt, ap);
	free(fmt);
	if (rc < 0)
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
