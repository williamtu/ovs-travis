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

struct ingress_policer;
struct netdev;
struct dp_packet_batch;

int netdev_qos_ingress_policer_run(struct ingress_policer *policer,
                                   struct dp_packet_batch *batch,
                                   bool should_steal);
int netdev_qos_set_policing(struct netdev *netdev, uint32_t policer_rate,
                            uint32_t policer_burst);

#endif /* netdev-qos.h */
