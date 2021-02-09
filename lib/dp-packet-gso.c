/*
 * Copyright (c) 2021 VMware, Inc.
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
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include "coverage.h"
#include "csum.h"
#include "dp-packet.h"
#include "dp-packet-gso.h"
#include "dpif-netdev.h"
#include "openvswitch/compiler.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(dp_packet_gso);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

/* Update ip header's total len, and id and update tcp header's
 * sent sequence number.  In the end, update ip and tcp csum.
 */
static void
update_ipv4_tcp_headers(const struct dp_packet *src, struct dp_packet **pkts,
                        uint16_t nb_segs)
{
    struct tcp_header *tcp;
    struct ip_header *ip;
    struct dp_packet *p;
    uint32_t tcp_seq;
    uint16_t ipid;
    int i;

    ip = dp_packet_l3(src);
    ipid = ntohs(ip->ip_id);
    tcp = dp_packet_l4(src);
    tcp_seq = ntohl(get_16aligned_be32(&tcp->tcp_seq));

    for (i = 0; i < nb_segs; i++) {
        p = pkts[i];

        ip = dp_packet_l3(p);
        ip->ip_tot_len = htons(dp_packet_l3_size(p));
        ip->ip_id = htons(ipid);
        ip->ip_csum = 0;
        ip->ip_csum = csum(ip, sizeof *ip);

        tcp = dp_packet_l4(p);
        put_16aligned_be32(&tcp->tcp_seq, htonl(tcp_seq));
        packet_csum_tcpudp(p);

        ipid += 1;
        tcp_seq += (const char *) dp_packet_tail(p) -
                   (const char *) dp_packet_l4(p) -
                   TCP_OFFSET(tcp->tcp_ctl) * 4;
    }
}

static void
hdr_segment_init(struct dp_packet *dst, const struct dp_packet *src)
{
    /* Copy the following fields into the returned buffer: l2_pad_size,
     * l2_5_ofs, l3_ofs, l4_ofs, cutlen, packet_type and md. */
    memcpy(&dst->l2_pad_size, &src->l2_pad_size,
           sizeof(struct dp_packet) -
           offsetof(struct dp_packet, l2_pad_size));

    *dp_packet_ol_flags_ptr(dst) = 0;
}

static int
gso_do_segment(const struct dp_packet *p, uint16_t hdr_offset,
               uint16_t pyld_unit_size, struct dp_packet **pout,
               uint16_t nb_pout)
{
    uint16_t nb_segs = 0;
    struct dp_packet *pkt;
    uint16_t seg_size;
    uint16_t pos = hdr_offset;
    int bytes_remaining = dp_packet_size(p) - hdr_offset;

    while (bytes_remaining > 0) {

        seg_size = (bytes_remaining >= pyld_unit_size) ?
                   pyld_unit_size : bytes_remaining;

        /* Create a new dp_packet, put payload, push header. */
        pkt = dp_packet_new_with_headroom(seg_size, hdr_offset);
        hdr_segment_init(pkt, p);
        dp_packet_put(pkt, (char *) dp_packet_data(p) + pos, seg_size);
        dp_packet_push(pkt, dp_packet_data(p), hdr_offset);

        pos += seg_size;
        bytes_remaining -= seg_size;
        pout[nb_segs] = pkt;
        nb_segs++;

        if (nb_segs > nb_pout) {
            VLOG_WARN_RL(&rl, "Not enough memory to process GSO.");
            nb_segs = -1;
            /* need to free dp_packet. */
            break;
        }
    }
    return nb_segs;
}

int
gso_tcp4_segment(struct dp_packet *p, uint16_t gso_size,
                 struct dp_packet **pout, uint16_t nb_pout)
{
    uint16_t pyld_unit_size, hdr_offset;
    int nb_segs;

    hdr_offset = (char *) dp_packet_get_tcp_payload(p) -
                 (char *) dp_packet_eth(p);
    pyld_unit_size = gso_size - hdr_offset;

    if (OVS_UNLIKELY(dp_packet_size(p) < ETH_PAYLOAD_MAX)) {
        VLOG_WARN_RL(&rl, "Packet size %u bytes too small for GSO.",
                     dp_packet_size(p));
        return -EINVAL;
    }

    nb_segs = gso_do_segment(p, hdr_offset, pyld_unit_size, pout, nb_pout);
    if (nb_segs > 0) {
        /* Update TCP checksum. */
        update_ipv4_tcp_headers(p, pout, nb_segs);
    }

    return nb_segs;
}
