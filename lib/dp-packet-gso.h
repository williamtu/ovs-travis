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

#ifndef DP_PACKET_GSO_H
#define DP_PACKET_GSO_H 1

#include <stdint.h>
#include <stdbool.h>

int gso_tcp4_segment(struct dp_packet *p, uint16_t gso_size,
                     struct dp_packet **pouts, uint16_t nb_pouts);
int gso_udp4_segment(struct dp_packet *p, uint16_t gso_size,
                     struct dp_packet **pouts, uint16_t nb_pouts);

int gso_tnl_tcp4_segment(struct dp_packet *p, uint16_t gso_size,
                         struct dp_packet **pouts, uint16_t nb_pouts);

#endif /* dp-packet-gso.h */
