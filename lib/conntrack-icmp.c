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

#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "openvswitch/vlog.h"
#include "conntrack-private.h"
#include "dp-packet.h"

VLOG_DEFINE_THIS_MODULE(conntrack_icmp);

enum OVS_PACKED_ENUM icmp_state {
    ICMPS_FIRST,
    ICMPS_REPLY,
};

struct conn_icmp {
    struct conn up;
    enum icmp_state state; /* 'conn' lock protected. */
};

static const enum ct_timeout icmp_timeouts[] = {
    [ICMPS_FIRST] = CT_TM_ICMP_FIRST,
    [ICMPS_REPLY] = CT_TM_ICMP_REPLY,
};

static struct conn_icmp *
conn_icmp_cast(const struct conn *conn)
{
    return CONTAINER_OF(conn, struct conn_icmp, up);
}

static bool
tp_has_icmp_reply(struct timeout_policy *tp, uint32_t *v)
{
    if (!tp) {
        return false;
    }
    if (tp->p.present & (1 << CT_DPIF_TP_ATTR_ICMP_REPLY)) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_ICMP_REPLY];
        VLOG_WARN("set icmp reply to %d", *v);
        return true;
    }
    return false;
}

static bool
tp_has_icmp_first(struct timeout_policy *tp, uint32_t *v)
{
    if (!tp) {
        return false;
    }
    if (tp->p.present & (1 << CT_DPIF_TP_ATTR_ICMP_FIRST)) {
        *v = tp->p.attrs[CT_DPIF_TP_ATTR_ICMP_FIRST];
        VLOG_WARN("set icmp first to %d", *v);
        return true;
    }
    return false;
}

static inline void
icmp_conn_update_expiration(struct conntrack *ct, struct conn *conn,
                            enum ct_timeout tm, long long now)
{
    struct timeout_policy *tp;
    uint32_t val;

    tp = timeout_policy_lookup(ct, conn->tpid);
    switch (tm) {
    case CT_TM_ICMP_FIRST:
        if (tp_has_icmp_first(tp, &val)) {
            conn_update_expiration_with_policy(ct, conn, tm, now, val);
        }
        break;
    case CT_TM_ICMP_REPLY:
        if (tp_has_icmp_reply(tp, &val)) {
            conn_update_expiration_with_policy(ct, conn, tm, now, val);
        }
        break;
    case CT_TM_OTHER_FIRST:
    case CT_TM_OTHER_BIDIR:
    case CT_TM_OTHER_MULTIPLE:
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
        conn_update_expiration(ct, conn, tm, now);
        break;
    }
}

static enum ct_update_res
icmp_conn_update(struct conntrack *ct, struct conn *conn_,
                 struct dp_packet *pkt OVS_UNUSED, bool reply, long long now)
{
    struct conn_icmp *conn = conn_icmp_cast(conn_);
    conn->state = reply ? ICMPS_REPLY : ICMPS_FIRST;
    icmp_conn_update_expiration(ct, &conn->up, icmp_timeouts[conn->state], now);

    return CT_UPDATE_VALID;
}

static bool
icmp4_valid_new(struct dp_packet *pkt)
{
    struct icmp_header *icmp = dp_packet_l4(pkt);

    return icmp->icmp_type == ICMP4_ECHO_REQUEST
           || icmp->icmp_type == ICMP4_INFOREQUEST
           || icmp->icmp_type == ICMP4_TIMESTAMP;
}

static bool
icmp6_valid_new(struct dp_packet *pkt)
{
    struct icmp6_header *icmp6 = dp_packet_l4(pkt);

    return icmp6->icmp6_type == ICMP6_ECHO_REQUEST;
}

static struct conn *
icmp_new_conn(struct conntrack *ct, struct dp_packet *pkt OVS_UNUSED,
              long long now)
{
    struct conn_icmp *conn = xzalloc(sizeof *conn);
    conn->state = ICMPS_FIRST;
    conn_init_expiration(ct, &conn->up, icmp_timeouts[conn->state], now, 0, true);

    return &conn->up;
}

struct ct_l4_proto ct_proto_icmp4 = {
    .new_conn = icmp_new_conn,
    .valid_new = icmp4_valid_new,
    .conn_update = icmp_conn_update,
};

struct ct_l4_proto ct_proto_icmp6 = {
    .new_conn = icmp_new_conn,
    .valid_new = icmp6_valid_new,
    .conn_update = icmp_conn_update,
};
