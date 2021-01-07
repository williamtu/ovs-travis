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

#ifndef NETDEV_QOS_H
#define NETDEV_QOS_H

#include <config.h>
#include <stdint.h>
#include <stdbool.h>

struct dp_packet_batch;
struct ingress_policer;
struct netdev;
struct netdev_linux;
struct netdev_queue_stats;
struct smap;
struct sset;

int netdev_qos_ingress_policer_run(struct ingress_policer *policer,
                                   struct dp_packet_batch *batch,
                                   bool should_steal);
int netdev_qos_set_policing(struct netdev *netdev, uint32_t policer_rate,
                            uint32_t policer_burst);
int netdev_qos_run(struct netdev_linux *dev, struct dp_packet_batch *batch,
                   bool should_steal);

int netdev_qos_get_qos_types(const struct netdev *netdev,
                              struct sset *types);
int netdev_qos_get_qos(const struct netdev *netdev,
                        const char **typep, struct smap *details);
int netdev_qos_set_qos(struct netdev *netdev, const char *type,
                        const struct smap *details);
int netdev_qos_get_queue(const struct netdev *netdev, uint32_t queue_id,
                          struct smap *details);
int netdev_qos_set_queue(struct netdev *netdev, uint32_t queue_id,
                          const struct smap *details);
int netdev_qos_delete_queue(struct netdev *netdev, uint32_t queue_id);
int netdev_qos_get_queue_stats(const struct netdev *netdev, uint32_t queue_id,
                                struct netdev_queue_stats *stats);
int netdev_qos_queue_dump_start(const struct netdev *netdev, void **statep);
int netdev_qos_queue_dump_next(const struct netdev *netdev, void *state_,
                                uint32_t *queue_idp, struct smap *details);
int netdev_qos_queue_dump_done(const struct netdev *netdev,
                                void *state_);

#define NETDEV_QOS_CLASS_COMMON                             \
     .get_qos_types = netdev_qos_get_qos_types,             \
     .get_qos = netdev_qos_get_qos,                         \
     .set_qos = netdev_qos_set_qos,                         \
     .get_queue = netdev_qos_get_queue,                     \
     .set_queue = netdev_qos_set_queue,                     \
     .delete_queue = netdev_qos_delete_queue,               \
     .get_queue_stats = netdev_qos_get_queue_stats,         \
     .queue_dump_start = netdev_qos_queue_dump_start,       \
     .queue_dump_next = netdev_qos_queue_dump_next,         \
     .queue_dump_done = netdev_qos_queue_dump_done

#endif /* netdev-qos.h */
