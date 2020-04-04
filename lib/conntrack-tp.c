/*
 * Copyright (c) 2020 VMware, Inc.
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

#include "conntrack-private.h"
#include "conntrack-tp.h"
#include "dp-packet.h"

#include "openvswitch/vlog.h"
VLOG_DEFINE_THIS_MODULE(conntrack_tp);

static const char *ct_timeout_str[] = {
#define CT_TIMEOUT(NAME, VALUE) #NAME
    CT_TIMEOUTS
#undef CT_TIMEOUT
};

static bool
tp_has_icmp_reply(struct timeout_policy *tp, uint32_t *v)
{
    if (tp && (tp->p.present & (1 << CT_DPIF_TP_ATTR_ICMP_REPLY))) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_ICMP_REPLY];
        return true;
    }
    return false;
}

static bool
tp_has_icmp_first(struct timeout_policy *tp, uint32_t *v)
{
    if (tp && (tp->p.present & (1 << CT_DPIF_TP_ATTR_ICMP_FIRST))) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_ICMP_FIRST];
        return true;
    }
    return false;
}

static bool
tp_has_udp_first(struct timeout_policy *tp, uint32_t *v)
{
    if (tp && (tp->p.present & (1 << CT_DPIF_TP_ATTR_UDP_FIRST))) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_UDP_FIRST];
        return true;
    }
    return false;
}

static bool
tp_has_udp_single(struct timeout_policy *tp, uint32_t *v)
{
    if (tp && (tp->p.present & (1 << CT_DPIF_TP_ATTR_UDP_SINGLE))) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_UDP_SINGLE];
        return true;
    }
    return false;
}

static bool
tp_has_udp_multiple(struct timeout_policy *tp, uint32_t *v)
{
    if (tp && (tp->p.present & (1 << CT_DPIF_TP_ATTR_UDP_MULTIPLE))) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_UDP_MULTIPLE];
        return true;
    }
    return false;
}

static bool
tp_has_tcp_syn_sent(struct timeout_policy *tp, uint32_t *v)
{
    if (tp && (tp->p.present & (1 << CT_DPIF_TP_ATTR_TCP_SYN_SENT))) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_TCP_SYN_SENT];
        return true;
    }
    return false;
}

static bool
tp_has_tcp_syn_recv(struct timeout_policy *tp, uint32_t *v)
{
    if (tp && (tp->p.present & (1 << CT_DPIF_TP_ATTR_TCP_SYN_RECV))) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_TCP_SYN_RECV];
        return true;
    }
    return false;
}

static bool
tp_has_tcp_established(struct timeout_policy *tp, uint32_t *v)
{
    if (tp && (tp->p.present & (1 << CT_DPIF_TP_ATTR_TCP_ESTABLISHED))) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_TCP_ESTABLISHED];
        return true;
    }
    return false;
}

static bool
tp_has_tcp_fin_wait(struct timeout_policy *tp, uint32_t *v)
{
    if (tp && (tp->p.present & (1 << CT_DPIF_TP_ATTR_TCP_FIN_WAIT))) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_TCP_FIN_WAIT];
        VLOG_WARN("set tcp closing");
        return true;
    }
    return false;
}

static bool
tp_has_tcp_time_wait(struct timeout_policy *tp, uint32_t *v)
{
    if (tp && (tp->p.present & (1 << CT_DPIF_TP_ATTR_TCP_TIME_WAIT))) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_TCP_TIME_WAIT];
        return true;
    }
    return false;
}

static bool
tp_has_tcp_closed(struct timeout_policy *tp, uint32_t *v)
{
    if (tp && (tp->p.present & (1 << CT_DPIF_TP_ATTR_TCP_CLOSE))) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_TCP_CLOSE];
        return true;
    }
    return false;
}

static void
conn_update_expiration_with_policy(struct conntrack *ct, struct conn *conn,
                                   enum ct_timeout tm, long long now)
{
    struct timeout_policy *tp;
    uint32_t val;

    tp = timeout_policy_lookup(ct, conn->tpid);
    if (!tp) {
        goto use_default;
    }
    switch (tm) {
    case CT_TM_TCP_FIRST_PACKET:
        if (tp_has_tcp_syn_sent(tp, &val)) {
            conn_update_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_TCP_OPENING: 
        if (tp_has_tcp_syn_recv(tp, &val)) {
            conn_update_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_TCP_ESTABLISHED:
        if (tp_has_tcp_established(tp, &val)) {
            conn_update_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_TCP_CLOSING:
        if (tp_has_tcp_fin_wait(tp, &val)) {
            conn_update_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_TCP_FIN_WAIT:
        if (tp_has_tcp_time_wait(tp, &val)) {
            conn_update_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_TCP_CLOSED:
        if (tp_has_tcp_closed(tp, &val)) {
            conn_update_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_OTHER_FIRST:
        if (tp_has_udp_first(tp, &val)) {
            conn_update_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_OTHER_BIDIR:
        if (tp_has_udp_single(tp, &val)) {
            conn_update_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_OTHER_MULTIPLE:
        if (tp_has_udp_multiple(tp, &val)) {
            conn_update_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_ICMP_FIRST:
        if (tp_has_icmp_first(tp, &val)) {
            conn_update_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_ICMP_REPLY:
        return; //FIXME
        if (tp_has_icmp_reply(tp, &val)) {
            conn_update_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case N_CT_TM:
    default:
        OVS_NOT_REACHED();
        break;
    }
use_default:
    conn_update_expiration(ct, conn, tm, now, 0, true);
}

static void
conn_init_expiration_with_policy(struct conntrack *ct, struct conn *conn,
                                 enum ct_timeout tm, long long now)
{
    struct timeout_policy *tp;
    uint32_t val;

    tp = timeout_policy_lookup(ct, conn->tpid);
    if (!tp) {
        goto use_default;
    }
    switch (tm) {
    case CT_TM_TCP_FIRST_PACKET:
        if (tp_has_tcp_syn_sent(tp, &val)) {
            conn_init_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_TCP_OPENING:
        if (tp_has_tcp_syn_recv(tp, &val)) {
            conn_init_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_TCP_ESTABLISHED:
        if (tp_has_tcp_established(tp, &val)) {
            conn_init_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_TCP_CLOSING:
        if (tp_has_tcp_fin_wait(tp, &val)) {
            conn_init_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_TCP_FIN_WAIT:
        if (tp_has_tcp_time_wait(tp, &val)) {
            conn_init_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_TCP_CLOSED:
        if (tp_has_tcp_closed(tp, &val)) {
            conn_init_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_OTHER_FIRST:
        if (tp_has_udp_first(tp, &val)) {
            conn_init_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_OTHER_BIDIR:
        if (tp_has_udp_single(tp, &val)) {
            conn_init_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_OTHER_MULTIPLE:
        if (tp_has_udp_multiple(tp, &val)) {
            conn_init_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_ICMP_FIRST:
        if (tp_has_icmp_first(tp, &val)) {
            conn_init_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case CT_TM_ICMP_REPLY:
        return; //FIXME
        if (tp_has_icmp_reply(tp, &val)) {
            conn_init_expiration(ct, conn, tm, now, val, false);
            return;
        }
        break;
    case N_CT_TM:
    default:
        OVS_NOT_REACHED();
        break;
    }
use_default:
    conn_init_expiration(ct, conn, tm, now, 0, true);
}

void
conn_init_expiration_with_tp(struct conntrack *ct, struct conn *conn,
                             enum ct_timeout tm, long long now)
{
    VLOG_DBG("Init timeout policy: %s", ct_timeout_str[tm]);
    conn_init_expiration_with_policy(ct, conn, tm, now);
}

void
conn_update_expiration_with_tp(struct conntrack *ct, struct conn *conn,
                               enum ct_timeout tm, long long now)
{
    VLOG_DBG("Update timeout policy: %s", ct_timeout_str[tm]);
    conn_update_expiration_with_policy(ct, conn, tm, now);
}
