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

static bool
tp_has_udp_first(struct timeout_policy *tp, uint32_t *v) /* other first */
{
    VLOG_INFO("%s", __func__);
    if (!tp) {
        return false;
    }
    if (tp->p.present & (1 << CT_DPIF_TP_ATTR_UDP_FIRST)) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_UDP_FIRST];
        VLOG_WARN("set udp first");
        return true;
    }
    return false;
}

static bool
tp_has_udp_single(struct timeout_policy *tp, uint32_t *v) /* other multiple */
{
    VLOG_INFO("%s", __func__);
    if (!tp) {
        return false;
    }
    if (tp->p.present & (1 << CT_DPIF_TP_ATTR_UDP_SINGLE)) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_UDP_SINGLE];
        VLOG_WARN("set udp single");
        return true;
    }
    return false;
}

static bool
tp_has_udp_multiple(struct timeout_policy *tp, uint32_t *v) /* other bidir */
{
    VLOG_INFO("%s", __func__);
    if (!tp) {
        return false;
    }
    if (tp->p.present & (1 << CT_DPIF_TP_ATTR_UDP_MULTIPLE)) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_UDP_MULTIPLE];
        VLOG_WARN("set udp multiple");
        return true;
    }
    return false;
}

void
other_conn_update_expiration(struct conntrack *ct, struct conn *conn,
                             enum ct_timeout tm, long long now)
{
    struct timeout_policy *tp;
    uint32_t val;

    VLOG_INFO("%s", __func__);
    tp = timeout_policy_lookup(ct, conn->tpid);
    if (tp) {
        VLOG_INFO("%s tpid = %d tm=%d", __func__, tp->p.id, tm);
    }
    switch (tm) {
    case CT_TM_OTHER_FIRST:
        if (tp_has_udp_first(tp, &val)) {
            conn_update_expiration_with_policy(ct, conn, tm, now, val);
            return;
        }
        break;
    case CT_TM_OTHER_BIDIR:
        if (tp_has_udp_single(tp, &val)) {
            conn_update_expiration_with_policy(ct, conn, tm, now, val);
            return;
        }
        break;
    case CT_TM_OTHER_MULTIPLE:
        if (tp_has_udp_multiple(tp, &val)) {
            conn_update_expiration_with_policy(ct, conn, tm, now, val);
            return;
        }
        break;
    case CT_TM_ICMP_FIRST:
    case CT_TM_ICMP_REPLY:
    case CT_TM_TCP_FIRST_PACKET:
    case CT_TM_TCP_OPENING:
    case CT_TM_TCP_ESTABLISHED:
    case CT_TM_TCP_CLOSING:
    case CT_TM_TCP_FIN_WAIT:
    case CT_TM_TCP_CLOSED:
    case N_CT_TM:
    default:
        VLOG_WARN("%s case not handled", __func__);
        break;
    }
    VLOG_INFO("UDP use default");
    conn_update_expiration(ct, conn, tm, now);
}

void
other_conn_init_expiration(struct conntrack *ct, struct conn *conn,
                             enum ct_timeout tm, long long now)
{
    struct timeout_policy *tp;
    uint32_t val;

    tp = timeout_policy_lookup(ct, conn->tpid);
    if (tp) {
        VLOG_INFO("%s tpid = %d tm=%d", __func__, tp->p.id, tm);
    }
    switch (tm) {
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
    case CT_TM_ICMP_REPLY:
    case CT_TM_TCP_FIRST_PACKET:
    case CT_TM_TCP_OPENING:
    case CT_TM_TCP_ESTABLISHED:
    case CT_TM_TCP_CLOSING:
    case CT_TM_TCP_FIN_WAIT:
    case CT_TM_TCP_CLOSED:
    case N_CT_TM:
    default:
        VLOG_WARN("%s case not handled", __func__);
        break;
    }

    VLOG_INFO("UDP use init default");
    conn_init_expiration(ct, conn, tm, now, 0, true);
}


