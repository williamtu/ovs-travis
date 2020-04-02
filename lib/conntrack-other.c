/*
 * Copyright (c) 2015-2019 Nicira, Inc.
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
#include "dp-packet.h"

#include "openvswitch/vlog.h"
VLOG_DEFINE_THIS_MODULE(conntrack_other);

enum OVS_PACKED_ENUM other_state {
    OTHERS_FIRST,
    OTHERS_MULTIPLE,
    OTHERS_BIDIR,
};

struct conn_other {
    struct conn up;
    enum other_state state; /* 'conn' lock protected. */
};

static const enum ct_timeout other_timeouts[] = {
    [OTHERS_FIRST] = CT_TM_OTHER_FIRST,
    [OTHERS_MULTIPLE] = CT_TM_OTHER_MULTIPLE,
    [OTHERS_BIDIR] = CT_TM_OTHER_BIDIR,
};

static struct conn_other *
conn_other_cast(const struct conn *conn)
{
    return CONTAINER_OF(conn, struct conn_other, up);
}

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

static inline void
other_conn_update_expiration(struct conntrack *ct, struct conn *conn,
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
            conn_update_expiration_with_policy(ct, conn, tm, now, val);
        }
        break;
    case CT_TM_OTHER_BIDIR:
        if (tp_has_udp_single(tp, &val)) {
            conn_update_expiration_with_policy(ct, conn, tm, now, val);
        }
        break;
    case CT_TM_OTHER_MULTIPLE:
        if (tp_has_udp_multiple(tp, &val)) {
            conn_update_expiration_with_policy(ct, conn, tm, now, val);
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
        VLOG_WARN("%s case not handled", __func__);
        break;
    default:
    VLOG_INFO("UDP use default");
        conn_update_expiration(ct, conn, tm, now);
        break;
    }
}

static enum ct_update_res
other_conn_update(struct conntrack *ct, struct conn *conn_,
                  struct dp_packet *pkt OVS_UNUSED, bool reply, long long now)
{
    struct conn_other *conn = conn_other_cast(conn_);
    enum ct_update_res ret = CT_UPDATE_VALID;

    VLOG_INFO("%s", __func__);
    if (reply && conn->state != OTHERS_BIDIR) {
        conn->state = OTHERS_BIDIR;
    } else if (conn->state == OTHERS_FIRST) {
        conn->state = OTHERS_MULTIPLE;
        ret = CT_UPDATE_VALID_NEW;
    }

    other_conn_update_expiration(ct, &conn->up, other_timeouts[conn->state], now);

    return ret;
}

static bool
other_valid_new(struct dp_packet *pkt OVS_UNUSED)
{
    return true;
}

static struct conn *
other_new_conn(struct conntrack *ct, struct dp_packet *pkt OVS_UNUSED,
               long long now)
{
    struct conn_other *conn;

    conn = xzalloc(sizeof *conn);
    conn->state = OTHERS_FIRST;

    conn_init_expiration(ct, &conn->up, other_timeouts[conn->state], now);

    return &conn->up;
}

struct ct_l4_proto ct_proto_other = {
    .new_conn = other_new_conn,
    .valid_new = other_valid_new,
    .conn_update = other_conn_update,
};
