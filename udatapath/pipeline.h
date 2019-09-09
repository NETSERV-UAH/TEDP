/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * Copyright (c) 2012, CPqD, Brazil  
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Ericsson Research nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef PIPELINE_H
#define PIPELINE_H 1


#include "datapath.h"
#include "packet.h"
#include "flow_table.h"
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"

#include <time.h>
#include <sys/time.h>

struct sender;

/****************************************************************************
 * A pipeline implementation. Processes messages through flow tables,
 * including the execution of instructions.
 ****************************************************************************/

/* A pipeline structure */
struct pipeline {
    struct datapath    *dp;
    struct flow_table  *tables[PIPELINE_TABLES];
};


/* Creates a pipeline. */
struct pipeline *
pipeline_create(struct datapath *dp);

/* Processes a packet in the pipeline. */
void
pipeline_process_packet(struct pipeline *pl, struct packet *pkt);


/* Handles a flow_mod message. */
ofl_err
pipeline_handle_flow_mod(struct pipeline *pl, struct ofl_msg_flow_mod *msg,
                         const struct sender *sender);

/* Handles a table_mod message. */
ofl_err
pipeline_handle_table_mod(struct pipeline *pl,
                          struct ofl_msg_table_mod *msg,
                          const struct sender *sender);

/* Handles a flow stats request. */
ofl_err
pipeline_handle_stats_request_flow(struct pipeline *pl,
                                   struct ofl_msg_multipart_request_flow *msg,
                                   const struct sender *sender);

/* Handles a table stats request. */
ofl_err
pipeline_handle_stats_request_table(struct pipeline *pl,
                                    struct ofl_msg_multipart_request_header *msg,
                                    const struct sender *sender);

/* Handles a table feature  request. */
ofl_err
pipeline_handle_stats_request_table_features_request(struct pipeline *pl,
                                    struct ofl_msg_multipart_request_header *msg,
                                    const struct sender *sender);

/* Handles an aggregate stats request. */
ofl_err
pipeline_handle_stats_request_aggregate(struct pipeline *pl,
                                  struct ofl_msg_multipart_request_flow *msg,
                                  const struct sender *sender);


/* Commands pipeline to check if any flow in any table is timed out. */
void
pipeline_timeout(struct pipeline *pl);

/* Detroys the pipeline. */
void
pipeline_destroy(struct pipeline *pl);

/*Modificacion*/
//vecinos globales para asi poder pasar y seleccionar envios
extern struct mac_to_port neighbor_table, Arppath_as_a_service_table;

/*Generate the path by protocol ARP PATH*/
void pipeline_arp_path(struct pipeline *pl, struct packet *pkt, struct mac_to_port *mac_port,
          struct mac_to_port *recovery_table, int TIME_RECOVERY, uint8_t *puerto_no_disponible, struct timeval * t_ini_recuperacion);
void pipeline_process_Uah(struct pipeline *pl, struct packet *pkt,
        struct mac_to_port *mac_port,   struct mac_to_port *recovery_table,
        uint8_t *puerto_no_disponible, struct timeval * t_ini_recuperacion);
/*logs*/

/*send mac host to the controller*/
int send_macs_to_ctr(struct pipeline *pl, struct packet *pkt);
//send frames unicast method ARP PATH
int arp_path_send_unicast(struct pipeline * pl, struct packet * pkt, struct mac_to_port * mac_port,
        struct mac_to_port * recovery_table, int TIME_RECOVERY, int out_port, uint8_t *puerto_no_disponible, struct timeval * t_ini_recuperacion);
//obtener direfencias de tiempo		
double timeval_diff_uah(struct timeval *a, struct timeval *b);
//encuentra datos reales en un paquete
int Found_date_in_pkt(int codigo, int busqueda, struct packet * pkt);
/*Fin Modificacion*/

#endif /* PIPELINE_H */