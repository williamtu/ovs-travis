/*
 * Copyright (c) 2021 VMWare, Inc.
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
#include "netdev-qos.h"
#include "netdev-linux.h"
#include "netdev-linux-private.h"

#include "dpif-netdev-perf.h"
#include "meter.h"
#include "openvswitch/thread.h"
#include "openvswitch/vlog.h"
#include "ovs-rcu.h"

VLOG_DEFINE_THIS_MODULE(netdev_qos);

struct ingress_policer {
    struct rte_meter_srtcm_params app_srtcm_params;
    struct rte_meter_srtcm in_policer;
    struct rte_meter_srtcm_profile in_prof;
    struct ovs_spin policer_lock;
};

static inline bool
netdev_afxdp_srtcm_policer_pkt_handle(struct rte_meter_srtcm *meter,
                                      struct rte_meter_srtcm_profile *profile,
                                      struct dp_packet *pkt, uint64_t time)
{
    uint32_t pkt_len = dp_packet_size(pkt) - ETH_HEADER_LEN;
    enum rte_color color = rte_meter_srtcm_color_blind_check(meter, profile,
                                                             time, pkt_len);
    return color == RTE_COLOR_GREEN;
}

static int
srtcm_policer_run_single_packet(struct rte_meter_srtcm *meter,
                                struct rte_meter_srtcm_profile *profile,
                                struct dp_packet_batch *batch,
                                bool should_steal)
{
    const size_t cnt = dp_packet_batch_size(batch);
    struct dp_packet *packet;
    int i;

    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, batch) {
        if (netdev_afxdp_srtcm_policer_pkt_handle(
                meter, profile, packet, cycles_counter_update__())) {
            dp_packet_batch_refill(batch, packet, i);
        } else {
            if (should_steal) {
                dp_packet_delete(packet);
            }
        }
    }

    return dp_packet_batch_size(batch);
}

int
netdev_qos_ingress_policer_run(struct ingress_policer *policer,
                               struct dp_packet_batch *batch,
                               bool should_steal)
{
    int cnt = 0;

    ovs_spin_lock(&policer->policer_lock);
    cnt = srtcm_policer_run_single_packet(&policer->in_policer,
                                          &policer->in_prof,
                                          batch, should_steal);
    ovs_spin_unlock(&policer->policer_lock);

    return cnt;
}

static struct ingress_policer *
netdev_qos_policer_construct(uint32_t rate, uint32_t burst)
{
    struct ingress_policer *policer = NULL;
    uint64_t rate_bytes;
    uint64_t burst_bytes;
    int err = 0;

    policer = xmalloc(sizeof *policer);
    ovs_spin_init(&policer->policer_lock);

    /* rte_meter requires bytes so convert kbits rate and burst to bytes. */
    rate_bytes = rate * 1000ULL / 8;
    burst_bytes = burst * 1000ULL / 8;

    policer->app_srtcm_params.cir = rate_bytes;
    policer->app_srtcm_params.cbs = burst_bytes;
    policer->app_srtcm_params.ebs = 0;
    err = rte_meter_srtcm_profile_config(&policer->in_prof,
                                         &policer->app_srtcm_params);
    if (!err) {
        err = rte_meter_srtcm_config(&policer->in_policer,
                                     &policer->in_prof);
    }
    if (err) {
        VLOG_ERR("Could not create rte meter for ingress policer");
        free(policer);
        return NULL;
    }

    return policer;
}

int
netdev_qos_set_policing(struct netdev *netdev, uint32_t policer_rate,
                        uint32_t policer_burst)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct ingress_policer *policer;

    /* Force to 0 if no rate specified,
     * default to 8000 kbits if burst is 0,
     * else stick with user-specified value.
     */
    policer_burst = (!policer_rate ? 0
                     : !policer_burst ? 8000
                     : policer_burst);

    ovs_mutex_lock(&dev->mutex);

    policer = ovsrcu_get_protected(struct ingress_policer *,
                                    &dev->ingress_policer);

    if (dev->policer_rate == policer_rate &&
        dev->policer_burst == policer_burst) {
        /* Assume that settings haven't changed since we last set them. */
        ovs_mutex_unlock(&dev->mutex);
        return 0;
    }

    /* Destroy any existing ingress policer for the device if one exists */
    if (policer) {
        ovsrcu_postpone(free, policer);
    }

    if (policer_rate != 0) {
        policer = netdev_qos_policer_construct(policer_rate, policer_burst);
    } else {
        policer = NULL;
    }
    ovsrcu_set(&dev->ingress_policer, policer);
    dev->policer_rate = policer_rate;
    dev->policer_burst = policer_burst;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}
