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

#include "dpif-netdev.h"
#include "dpif-netdev-perf.h"
#include "meter.h"
#include "openvswitch/thread.h"
#include "openvswitch/vlog.h"
#include "ovs-rcu.h"
#include "smap.h"
#include "sset.h"

VLOG_DEFINE_THIS_MODULE(netdev_qos);

struct ingress_policer {
    struct rte_meter_srtcm_params app_srtcm_params;
    struct rte_meter_srtcm in_policer;
    struct rte_meter_srtcm_profile in_prof;
    struct ovs_spin policer_lock;
};

/* Quality of Service */

/* An instance of a QoS configuration.  Always associated with a particular
 * network device.
 *
 * Each QoS implementation subclasses this with whatever additional data it
 * needs.
 */
struct qos_conf {
    const struct netdev_qos_ops *ops;
    struct ovs_spin lock;
};

/* QoS queue information used by the netdev queue dump functions. */
struct netdev_qos_queue_state {
    uint32_t *queues;
    size_t cur_queue;
    size_t n_queues;
};

/* A particular implementation of QoS operations.
 *
 * The functions below return 0 if successful or a positive errno value on
 * failure, except where otherwise noted. All of them must be provided, except
 * where otherwise noted.
 */
struct netdev_qos_ops {

    /* Name of the QoS type */
    const char *qos_name;

    /* Called to construct a qos_conf object. The implementation should make
     * the appropriate calls to configure QoS according to 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     *
     * This function must return 0 if and only if it sets '*conf' to an
     * initialized 'struct qos_conf'.
     *
     * For all QoS implementations it should always be non-null.
     */
    int (*qos_construct)(const struct smap *details, struct qos_conf **conf);

    /* Destroys the data structures allocated by the implementation as part of
     * 'qos_conf'.
     *
     * For all QoS implementations it should always be non-null.
     */
    void (*qos_destruct)(struct qos_conf *conf);

    /* Retrieves details of 'conf' configuration into 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     */
    int (*qos_get)(const struct qos_conf *conf, struct smap *details);

    /* Returns true if 'conf' is already configured according to 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     *
     * For all QoS implementations it should always be non-null.
     */
    bool (*qos_is_equal)(const struct qos_conf *conf,
                         const struct smap *details);

    /* Modify an array of rte_mbufs. The modification is specific to
     * each qos implementation.
     *
     * The function should take and array of mbufs and an int representing
     * the current number of mbufs present in the array.
     *
     * After the function has performed a qos modification to the array of
     * mbufs it returns an int representing the number of mbufs now present in
     * the array. This value is can then be passed to the port send function
     * along with the modified array for transmission.
     *
     * For all QoS implementations it should always be non-null.
     */
    int (*qos_run)(struct qos_conf *qos_conf, struct dp_packet_batch *pkts,
                   bool should_steal);

    /* Called to construct a QoS Queue. The implementation should make
     * the appropriate calls to configure QoS Queue according to 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     *
     * This function must return 0 if and only if it constructs
     * QoS queue successfully.
     */
    int (*qos_queue_construct)(const struct smap *details,
                               uint32_t queue_id, struct qos_conf *conf);

    /* Destroys the QoS Queue. */
    void (*qos_queue_destruct)(struct qos_conf *conf, uint32_t queue_id);

    /* Retrieves details of QoS Queue configuration into 'details'.
     *
     * The contents of 'details' should be documented as valid for 'ovs_name'
     * in the "other_config" column in the "QoS" table in vswitchd/vswitch.xml
     * (which is built as ovs-vswitchd.conf.db(8)).
     */
    int (*qos_queue_get)(struct smap *details, uint32_t queue_id,
                         const struct qos_conf *conf);

    /* Retrieves statistics of QoS Queue configuration into 'stats'. */
    int (*qos_queue_get_stats)(const struct qos_conf *conf, uint32_t queue_id,
                               struct netdev_queue_stats *stats);

    /* Setup the 'netdev_qos_queue_state' structure used by the dpdk queue
     * dump functions.
     */
    int (*qos_queue_dump_state_init)(const struct qos_conf *conf,
                                     struct netdev_qos_queue_state *state);
};

/* netdev_qos_ops for each type of user space QoS implementation. */
static const struct netdev_qos_ops egress_policer_ops;
static const struct netdev_qos_ops trtcm_policer_ops;

/*
 * Array of netdev_qos_ops, contains pointer to all supported QoS
 * operations.
 */
static const struct netdev_qos_ops *const qos_confs[] = {
    &egress_policer_ops,
    &trtcm_policer_ops,
    NULL
};

static inline bool
netdev_qos_srtcm_policer_pkt_handle(struct rte_meter_srtcm *meter,
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
        if (netdev_qos_srtcm_policer_pkt_handle(
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

int
netdev_qos_run(struct netdev_linux *dev, struct dp_packet_batch *batch,
               bool should_steal)
{
    struct qos_conf *qos_conf = ovsrcu_get(struct qos_conf *, &dev->qos_conf);
    int cnt = dp_packet_batch_size(batch);

    if (qos_conf) {
        ovs_spin_lock(&qos_conf->lock);
        cnt = qos_conf->ops->qos_run(qos_conf, batch, should_steal);
        ovs_spin_unlock(&qos_conf->lock);
    }

    return cnt;
}

/* QoS Functions */

/*
 * Initialize QoS configuration operations.
 */
static void
qos_conf_init(struct qos_conf *conf, const struct netdev_qos_ops *ops)
{
    conf->ops = ops;
    ovs_spin_init(&conf->lock);
}

/*
 * Search existing QoS operations in qos_ops and compare each set of
 * operations qos_name to name. Return a netdev_qos_ops pointer to a match,
 * else return NULL
 */
static const struct netdev_qos_ops *
qos_lookup_name(const char *name)
{
    const struct netdev_qos_ops *const *opsp;

    for (opsp = qos_confs; *opsp != NULL; opsp++) {
        const struct netdev_qos_ops *ops = *opsp;
        if (!strcmp(name, ops->qos_name)) {
            return ops;
        }
    }
    return NULL;
}

int
netdev_qos_get_qos_types(const struct netdev *netdev OVS_UNUSED,
                           struct sset *types)
{
    const struct netdev_qos_ops *const *opsp;

    for (opsp = qos_confs; *opsp != NULL; opsp++) {
        const struct netdev_qos_ops *ops = *opsp;
        if (ops->qos_construct && ops->qos_name[0] != '\0') {
            sset_add(types, ops->qos_name);
        }
    }
    return 0;
}

int
netdev_qos_get_qos(const struct netdev *netdev,
                    const char **typep, struct smap *details)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct qos_conf *qos_conf;
    int error = 0;

    ovs_mutex_lock(&dev->mutex);
    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
    if (qos_conf) {
        *typep = qos_conf->ops->qos_name;
        error = (qos_conf->ops->qos_get
                 ? qos_conf->ops->qos_get(qos_conf, details): 0);
    } else {
        /* No QoS configuration set, return an empty string */
        *typep = "";
    }
    ovs_mutex_unlock(&dev->mutex);

    return error;
}

int
netdev_qos_set_qos(struct netdev *netdev, const char *type,
                    const struct smap *details)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    const struct netdev_qos_ops *new_ops = NULL;
    struct qos_conf *qos_conf, *new_qos_conf = NULL;
    int error = 0;

    ovs_mutex_lock(&dev->mutex);

    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);

    new_ops = qos_lookup_name(type);

    if (!new_ops || !new_ops->qos_construct) {
        new_qos_conf = NULL;
        if (type && type[0]) {
            error = EOPNOTSUPP;
        }
    } else if (qos_conf && qos_conf->ops == new_ops
               && qos_conf->ops->qos_is_equal(qos_conf, details)) {
        new_qos_conf = qos_conf;
    } else {
        error = new_ops->qos_construct(details, &new_qos_conf);
    }

    if (error) {
        VLOG_ERR("Failed to set QoS type %s on port %s: %s",
                 type, netdev->name, ovs_strerror(error));
    }

    if (new_qos_conf != qos_conf) {
        ovsrcu_set(&dev->qos_conf, new_qos_conf);
        if (qos_conf) {
            ovsrcu_postpone(qos_conf->ops->qos_destruct, qos_conf);
        }
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

int
netdev_qos_get_queue(const struct netdev *netdev, uint32_t queue_id,
                      struct smap *details)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct qos_conf *qos_conf;
    int error = 0;

    ovs_mutex_lock(&dev->mutex);

    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
    if (!qos_conf || !qos_conf->ops || !qos_conf->ops->qos_queue_get) {
        error = EOPNOTSUPP;
    } else {
        error = qos_conf->ops->qos_queue_get(details, queue_id, qos_conf);
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

int
netdev_qos_set_queue(struct netdev *netdev, uint32_t queue_id,
                      const struct smap *details)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct qos_conf *qos_conf;
    int error = 0;

    ovs_mutex_lock(&dev->mutex);

    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
    if (!qos_conf || !qos_conf->ops || !qos_conf->ops->qos_queue_construct) {
        error = EOPNOTSUPP;
    } else {
        error = qos_conf->ops->qos_queue_construct(details, queue_id,
                                                   qos_conf);
    }

    if (error && error != EOPNOTSUPP) {
        VLOG_ERR("Failed to set QoS queue %d on port %s: %s",
                 queue_id, netdev_get_name(netdev), ovs_strerror(error));
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

int
netdev_qos_delete_queue(struct netdev *netdev, uint32_t queue_id)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct qos_conf *qos_conf;
    int error = 0;

    ovs_mutex_lock(&dev->mutex);

    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
    if (qos_conf && qos_conf->ops && qos_conf->ops->qos_queue_destruct) {
        qos_conf->ops->qos_queue_destruct(qos_conf, queue_id);
    } else {
        error =  EOPNOTSUPP;
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

int
netdev_qos_get_queue_stats(const struct netdev *netdev, uint32_t queue_id,
                            struct netdev_queue_stats *stats)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct qos_conf *qos_conf;
    int error = 0;

    ovs_mutex_lock(&dev->mutex);

    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
    if (qos_conf && qos_conf->ops && qos_conf->ops->qos_queue_get_stats) {
        qos_conf->ops->qos_queue_get_stats(qos_conf, queue_id, stats);
    } else {
        error = EOPNOTSUPP;
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

int
netdev_qos_queue_dump_start(const struct netdev *netdev, void **statep)
{
    int error = 0;
    struct qos_conf *qos_conf;
    struct netdev_linux *dev = netdev_linux_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

    qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
    if (qos_conf && qos_conf->ops
        && qos_conf->ops->qos_queue_dump_state_init) {
        struct netdev_qos_queue_state *state;

        *statep = state = xmalloc(sizeof *state);
        error = qos_conf->ops->qos_queue_dump_state_init(qos_conf, state);
    } else {
        error = EOPNOTSUPP;
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

int
netdev_qos_queue_dump_next(const struct netdev *netdev, void *state_,
                            uint32_t *queue_idp, struct smap *details)
{
    struct netdev_linux *dev = netdev_linux_cast(netdev);
    struct netdev_qos_queue_state *state = state_;
    struct qos_conf *qos_conf;
    int error = EOF;

    ovs_mutex_lock(&dev->mutex);

    while (state->cur_queue < state->n_queues) {
        uint32_t queue_id = state->queues[state->cur_queue++];

        qos_conf = ovsrcu_get_protected(struct qos_conf *, &dev->qos_conf);
        if (qos_conf && qos_conf->ops && qos_conf->ops->qos_queue_get) {
            *queue_idp = queue_id;
            error = qos_conf->ops->qos_queue_get(details, queue_id, qos_conf);
            break;
        }
    }

    ovs_mutex_unlock(&dev->mutex);

    return error;
}

int
netdev_qos_queue_dump_done(const struct netdev *netdev OVS_UNUSED,
                           void *state_)
{
    struct netdev_qos_queue_state *state = state_;

    free(state->queues);
    free(state);
    return 0;
}

/* egress-policer details */

struct egress_policer {
    struct qos_conf qos_conf;
    struct rte_meter_srtcm_params app_srtcm_params;
    struct rte_meter_srtcm egress_meter;
    struct rte_meter_srtcm_profile egress_prof;
};

static void
egress_policer_details_to_param(const struct smap *details,
                                struct rte_meter_srtcm_params *params)
{
    memset(params, 0, sizeof *params);
    params->cir = smap_get_ullong(details, "cir", 0);
    params->cbs = smap_get_ullong(details, "cbs", 0);
    params->ebs = 0;
}

static int
egress_policer_qos_construct(const struct smap *details,
                             struct qos_conf **conf)
{
    struct egress_policer *policer;
    int err = 0;

    policer = xmalloc(sizeof *policer);
    qos_conf_init(&policer->qos_conf, &egress_policer_ops);
    egress_policer_details_to_param(details, &policer->app_srtcm_params);
    err = rte_meter_srtcm_profile_config(&policer->egress_prof,
                                         &policer->app_srtcm_params);
    if (!err) {
        err = rte_meter_srtcm_config(&policer->egress_meter,
                                     &policer->egress_prof);
    }

    if (!err) {
        *conf = &policer->qos_conf;
    } else {
        VLOG_ERR("Could not create rte meter for egress policer");
        free(policer);
        *conf = NULL;
        err = -err;
    }

    return err;
}

static void
egress_policer_qos_destruct(struct qos_conf *conf)
{
    struct egress_policer *policer = CONTAINER_OF(conf, struct egress_policer,
                                                  qos_conf);
    free(policer);
}

static int
egress_policer_qos_get(const struct qos_conf *conf, struct smap *details)
{
    struct egress_policer *policer =
        CONTAINER_OF(conf, struct egress_policer, qos_conf);

    smap_add_format(details, "cir", "%"PRIu64, policer->app_srtcm_params.cir);
    smap_add_format(details, "cbs", "%"PRIu64, policer->app_srtcm_params.cbs);

    return 0;
}

static bool
egress_policer_qos_is_equal(const struct qos_conf *conf,
                            const struct smap *details)
{
    struct egress_policer *policer =
        CONTAINER_OF(conf, struct egress_policer, qos_conf);
    struct rte_meter_srtcm_params params;

    egress_policer_details_to_param(details, &params);

    return !memcmp(&params, &policer->app_srtcm_params, sizeof params);
}

static int
egress_policer_run(struct qos_conf *conf, struct dp_packet_batch *pkts,
                   bool should_steal)
{
    int cnt = 0;
    struct egress_policer *policer =
        CONTAINER_OF(conf, struct egress_policer, qos_conf);

    cnt = srtcm_policer_run_single_packet(&policer->egress_meter,
                                          &policer->egress_prof, pkts,
                                          should_steal);

    return cnt;
}

static const struct netdev_qos_ops egress_policer_ops = {
    .qos_name = "egress-policer",    /* qos_name */
    .qos_construct = egress_policer_qos_construct,
    .qos_destruct = egress_policer_qos_destruct,
    .qos_get = egress_policer_qos_get,
    .qos_is_equal = egress_policer_qos_is_equal,
    .qos_run = egress_policer_run
};

/* trtcm-policer details */

struct trtcm_policer {
    struct qos_conf qos_conf;
    struct rte_meter_trtcm_rfc4115_params meter_params;
    struct rte_meter_trtcm_rfc4115_profile meter_profile;
    struct rte_meter_trtcm_rfc4115 meter;
    struct netdev_queue_stats stats;
    struct hmap queues;
};

struct trtcm_policer_queue {
    struct hmap_node hmap_node;
    uint32_t queue_id;
    struct rte_meter_trtcm_rfc4115_params meter_params;
    struct rte_meter_trtcm_rfc4115_profile meter_profile;
    struct rte_meter_trtcm_rfc4115 meter;
    struct netdev_queue_stats stats;
};

static void
trtcm_policer_details_to_param(const struct smap *details,
                               struct rte_meter_trtcm_rfc4115_params *params)
{
    memset(params, 0, sizeof *params);
    params->cir = smap_get_ullong(details, "cir", 0);
    params->eir = smap_get_ullong(details, "eir", 0);
    params->cbs = smap_get_ullong(details, "cbs", 0);
    params->ebs = smap_get_ullong(details, "ebs", 0);
}

static void
trtcm_policer_param_to_detail(
    const struct rte_meter_trtcm_rfc4115_params *params,
    struct smap *details)
{
    smap_add_format(details, "cir", "%"PRIu64, params->cir);
    smap_add_format(details, "eir", "%"PRIu64, params->eir);
    smap_add_format(details, "cbs", "%"PRIu64, params->cbs);
    smap_add_format(details, "ebs", "%"PRIu64, params->ebs);
}


static int
trtcm_policer_qos_construct(const struct smap *details,
                            struct qos_conf **conf)
{
    struct trtcm_policer *policer;
    int err = 0;

    policer = xmalloc(sizeof *policer);
    qos_conf_init(&policer->qos_conf, &trtcm_policer_ops);
    trtcm_policer_details_to_param(details, &policer->meter_params);
    err = rte_meter_trtcm_rfc4115_profile_config(&policer->meter_profile,
                                                 &policer->meter_params);
    if (!err) {
        err = rte_meter_trtcm_rfc4115_config(&policer->meter,
                                             &policer->meter_profile);
    }

    if (!err) {
        *conf = &policer->qos_conf;
        memset(&policer->stats, 0, sizeof policer->stats);
        hmap_init(&policer->queues);
    } else {
        free(policer);
        *conf = NULL;
        err = -err;
    }

    return err;
}

static void
trtcm_policer_qos_destruct(struct qos_conf *conf)
{
    struct trtcm_policer_queue *queue, *next_queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    HMAP_FOR_EACH_SAFE (queue, next_queue, hmap_node, &policer->queues) {
        hmap_remove(&policer->queues, &queue->hmap_node);
        free(queue);
    }
    hmap_destroy(&policer->queues);
    free(policer);
}

static int
trtcm_policer_qos_get(const struct qos_conf *conf, struct smap *details)
{
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    trtcm_policer_param_to_detail(&policer->meter_params, details);
    return 0;
}

static bool
trtcm_policer_qos_is_equal(const struct qos_conf *conf,
                           const struct smap *details)
{
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);
    struct rte_meter_trtcm_rfc4115_params params;

    trtcm_policer_details_to_param(details, &params);

    return !memcmp(&params, &policer->meter_params, sizeof params);
}

static struct trtcm_policer_queue *
trtcm_policer_qos_find_queue(struct trtcm_policer *policer, uint32_t queue_id)
{
    struct trtcm_policer_queue *queue;
    HMAP_FOR_EACH_WITH_HASH (queue, hmap_node, hash_2words(queue_id, 0),
                             &policer->queues) {
        if (queue->queue_id == queue_id) {
            return queue;
        }
    }
    return NULL;
}

static inline bool
trtcm_policer_run_single_packet(struct trtcm_policer *policer,
                                struct dp_packet *pkt, uint64_t time)
{
    enum rte_color pkt_color;
    struct trtcm_policer_queue *queue;
    uint32_t pkt_len = dp_packet_size(pkt) - ETH_HEADER_LEN;

    queue = trtcm_policer_qos_find_queue(policer, pkt->md.skb_priority);
    if (!queue) {
        /* If no queue is found, use the default queue, which MUST exist. */
        queue = trtcm_policer_qos_find_queue(policer, 0);
        if (!queue) {
            return false;
        }
    }

    pkt_color =
        rte_meter_trtcm_rfc4115_color_blind_check(&queue->meter,
                                                  &queue->meter_profile,
                                                  time, pkt_len);

    if (pkt_color == RTE_COLOR_RED) {
        queue->stats.tx_errors++;
    } else {
        queue->stats.tx_bytes += pkt_len;
        queue->stats.tx_packets++;
    }

    pkt_color =
        rte_meter_trtcm_rfc4115_color_aware_check(&policer->meter,
                                                  &policer->meter_profile,
                                                  time, pkt_len, pkt_color);

    if (pkt_color == RTE_COLOR_RED) {
        policer->stats.tx_errors++;
        return false;
    }

    policer->stats.tx_bytes += pkt_len;
    policer->stats.tx_packets++;
    return true;
}

static int
trtcm_policer_run(struct qos_conf *conf, struct dp_packet_batch *batch,
                  bool should_steal)
{
    int i = 0;
    const size_t cnt = dp_packet_batch_size(batch);
    struct dp_packet *pkt;
    uint64_t current_time = cycles_counter_update__();

    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, pkt, batch) {
         if (trtcm_policer_run_single_packet(policer, pkt, current_time)) {
            dp_packet_batch_refill(batch, pkt, i);
        } else {
            if (should_steal) {
                dp_packet_delete(pkt);
            }
        }
   }
   return dp_packet_batch_size(batch);
}

static int
trtcm_policer_qos_queue_construct(const struct smap *details,
                                  uint32_t queue_id, struct qos_conf *conf)
{
    int err = 0;
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    queue = trtcm_policer_qos_find_queue(policer, queue_id);
    if (!queue) {
        queue = xmalloc(sizeof *queue);
        queue->queue_id = queue_id;
        memset(&queue->stats, 0, sizeof queue->stats);
        queue->stats.created = time_msec();
        hmap_insert(&policer->queues, &queue->hmap_node,
                    hash_2words(queue_id, 0));
    }
    if (queue_id == 0 && smap_is_empty(details)) {
        /* No default queue configured, use port values */
        memcpy(&queue->meter_params, &policer->meter_params,
               sizeof queue->meter_params);
    } else {
        trtcm_policer_details_to_param(details, &queue->meter_params);
    }

    err = rte_meter_trtcm_rfc4115_profile_config(&queue->meter_profile,
                                                 &queue->meter_params);

    if (!err) {
        err = rte_meter_trtcm_rfc4115_config(&queue->meter,
                                             &queue->meter_profile);
    }
    if (err) {
        hmap_remove(&policer->queues, &queue->hmap_node);
        free(queue);
        err = -err;
    }
    return err;
}

static void
trtcm_policer_qos_queue_destruct(struct qos_conf *conf, uint32_t queue_id)
{
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    queue = trtcm_policer_qos_find_queue(policer, queue_id);
    if (queue) {
        hmap_remove(&policer->queues, &queue->hmap_node);
        free(queue);
    }
}

static int
trtcm_policer_qos_queue_get(struct smap *details, uint32_t queue_id,
                            const struct qos_conf *conf)
{
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    queue = trtcm_policer_qos_find_queue(policer, queue_id);
    if (!queue) {
        return EINVAL;
    }

    trtcm_policer_param_to_detail(&queue->meter_params, details);
    return 0;
}

static int
trtcm_policer_qos_queue_get_stats(const struct qos_conf *conf,
                                  uint32_t queue_id,
                                  struct netdev_queue_stats *stats)
{
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    queue = trtcm_policer_qos_find_queue(policer, queue_id);
    if (!queue) {
        return EINVAL;
    }
    memcpy(stats, &queue->stats, sizeof *stats);
    return 0;
}

static int
trtcm_policer_qos_queue_dump_state_init(const struct qos_conf *conf,
                                        struct netdev_qos_queue_state *state)
{
    uint32_t i = 0;
    struct trtcm_policer_queue *queue;
    struct trtcm_policer *policer = CONTAINER_OF(conf, struct trtcm_policer,
                                                 qos_conf);

    state->n_queues = hmap_count(&policer->queues);
    state->cur_queue = 0;
    state->queues = xmalloc(state->n_queues * sizeof *state->queues);

    HMAP_FOR_EACH (queue, hmap_node, &policer->queues) {
        state->queues[i++] = queue->queue_id;
    }
    return 0;
}

static const struct netdev_qos_ops trtcm_policer_ops = {
    .qos_name = "trtcm-policer",
    .qos_construct = trtcm_policer_qos_construct,
    .qos_destruct = trtcm_policer_qos_destruct,
    .qos_get = trtcm_policer_qos_get,
    .qos_is_equal = trtcm_policer_qos_is_equal,
    .qos_run = trtcm_policer_run,
    .qos_queue_construct = trtcm_policer_qos_queue_construct,
    .qos_queue_destruct = trtcm_policer_qos_queue_destruct,
    .qos_queue_get = trtcm_policer_qos_queue_get,
    .qos_queue_get_stats = trtcm_policer_qos_queue_get_stats,
    .qos_queue_dump_state_init = trtcm_policer_qos_queue_dump_state_init
};
