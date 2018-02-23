/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "backtrace.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(backtrace);

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#define UNW_LOCAL_ONLY
#include <libunwind.h>

void dump_stack (void) {
  unw_cursor_t cursor; unw_context_t uc;
  unw_word_t ip, sp, offp;
  char name[256];

  unw_getcontext(&uc);
  unw_init_local(&cursor, &uc);
  while (unw_step(&cursor) > 0) {
    unw_get_proc_name(&cursor, name, 256, &offp);
    unw_get_reg(&cursor, UNW_REG_IP, &ip);
    unw_get_reg(&cursor, UNW_REG_SP, &sp);
    VLOG_INFO("func:%s ip:%lx sp:%lx\n", name, (long) ip, (long) sp);
  }
}

void
backtrace_capture(struct backtrace *b)
{
    void *frames[BACKTRACE_MAX_FRAMES];
    char **symbols;
    int i;

    b->n_frames = backtrace(frames, BACKTRACE_MAX_FRAMES);
    symbols = backtrace_symbols(frames, b->n_frames);
    for (i = 0; i < b->n_frames; i++) {
        b->frames[i] = (uintptr_t) frames[i];
        strcpy(b->symbols[i], symbols[i]);
    }
    free(symbols);
}

#else
void
backtrace_capture(struct backtrace *backtrace)
{
    backtrace->n_frames = 0;
}
#endif

static char *
backtrace_format(const struct backtrace *b, struct ds *ds)
{
    if (b->n_frames) {
        int i;

        ds_put_cstr(ds, " (backtrace:");
        for (i = 0; i < b->n_frames; i++) {
            ds_put_format(ds, " %s", b->symbols[i]);
            ds_put_format(ds, " 0x%08"PRIxPTR"\n", b->frames[i]);
        }
        ds_put_cstr(ds, ")");
    }

    return ds_cstr(ds);
}

void
log_backtrace_at(const char *msg, const char *where)
{
    struct backtrace b;
    struct ds ds = DS_EMPTY_INITIALIZER;

    for (int i = 0; i < BACKTRACE_MAX_FRAMES; i++) {
        b.symbols[i] = malloc(64);
        if (!b.symbols[i]) {
            goto out;
        }
    }

    backtrace_capture(&b);
    if (msg) {
        ds_put_format(&ds, "%s ", msg);
    }

    ds_put_cstr(&ds, where);
    VLOG_ERR("%s", backtrace_format(&b, &ds));

    ds_destroy(&ds);
    dump_stack();
out:
    for (int i = 0; i < BACKTRACE_MAX_FRAMES; i++) {
        free(b.symbols[i]);
    }
}
