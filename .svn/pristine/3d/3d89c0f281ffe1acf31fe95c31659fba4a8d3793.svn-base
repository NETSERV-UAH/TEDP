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

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include "datapath.h"
#include "dp_buffers.h"
#include "dp_actions.h"
#include "packet.h"
#include "packets.h"
#include "action_set.h"
#include "ofpbuf.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-print.h"
#include "util.h"

#define PORT_HOST 0
#define PORT_CORE 1
#define PORT_AGR 2 
#define PORT_TOR 3


struct packet *
packet_create(struct datapath *dp, uint32_t in_port,
    struct ofpbuf *buf, bool packet_out) {
    struct packet *pkt;

    pkt = xmalloc(sizeof(struct packet));

    pkt->dp         = dp;
    pkt->buffer     = buf;
    pkt->in_port    = in_port;
    pkt->action_set = action_set_create(dp->exp);

    pkt->packet_out       = packet_out;
    pkt->out_group        = OFPG_ANY;
    pkt->out_port         = OFPP_ANY;
    pkt->out_port_max_len = 0;
    pkt->out_queue        = 0;
    pkt->buffer_id        = NO_BUFFER;
    pkt->table_id         = 0;

    pkt->handle_std = packet_handle_std_create(pkt);
    return pkt;
}

struct packet *
packet_clone(struct packet *pkt) {
    struct packet *clone;

    clone = xmalloc(sizeof(struct packet));
    clone->dp         = pkt->dp;
    clone->buffer     = ofpbuf_clone(pkt->buffer);
    clone->in_port    = pkt->in_port;
    /* There is no case we need to keep the action-set, but if it's needed
     * we could add a parameter to the function... Jean II
     * clone->action_set = action_set_clone(pkt->action_set);
     */
    clone->action_set = action_set_create(pkt->dp->exp);


    clone->packet_out       = pkt->packet_out;
    clone->out_group        = OFPG_ANY;
    clone->out_port         = OFPP_ANY;
    clone->out_port_max_len = 0;
    clone->out_queue        = 0;
    clone->buffer_id        = NO_BUFFER; // the original is saved in buffer,
                                         // but this buffer is a copy of that,
                                         // and might be altered later
    clone->table_id         = pkt->table_id;

    clone->handle_std = packet_handle_std_clone(clone, pkt->handle_std);

    return clone;
}

void
packet_destroy(struct packet *pkt) {
    /* If packet is saved in a buffer, do not destroy it,
     * if buffer is still valid */
     
    if (pkt->buffer_id != NO_BUFFER) {
        if (dp_buffers_is_alive(pkt->dp->buffers, pkt->buffer_id)) {
            return;
        } else {
            dp_buffers_discard(pkt->dp->buffers, pkt->buffer_id, false);
        }
    }

    action_set_destroy(pkt->action_set);
    ofpbuf_delete(pkt->buffer);
    packet_handle_std_destroy(pkt->handle_std);
    free(pkt);
}

char *
packet_to_string(struct packet *pkt) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    fprintf(stream, "pkt{in=\"");
    ofl_port_print(stream, pkt->in_port);
    fprintf(stream, "\", actset=");
    action_set_print(stream, pkt->action_set);
    fprintf(stream, ", pktout=\"%u\", ogrp=\"", pkt->packet_out);
    ofl_group_print(stream, pkt->out_group);
    fprintf(stream, "\", oprt=\"");
    ofl_port_print(stream, pkt->out_port);
    fprintf(stream, "\", buffer=\"");
    ofl_buffer_print(stream, pkt->buffer_id);
    fprintf(stream, "\", std=");
    packet_handle_std_print(stream, pkt->handle_std);
    fprintf(stream, "}");

    fclose(stream);
    return str;
}
//Modificacion UAH
struct packet * packet_hello_create(struct datapath *dp, uint32_t in_port, bool packet_out)
{
	struct packet *pkt = NULL;
	struct ofpbuf *buf = NULL;
	uint8_t Total[45], Mac[ETH_ADDR_LEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF} , type_array[2] = {0x76, 0x98};
	uint8_t posicion = 1; // Core = 1, Agr = 2, Tor = 3
	uint16_t type = 0x9876;

	//Creamos el buffer del paquete
	buf = ofpbuf_new(46); //sizeof(struct eth_header));
	//lo rellenamos con la broadcast
	ofpbuf_put(buf, Mac,ETH_ADDR_LEN);
	//lo rellenamos con la mac switch       
	ofpbuf_put(buf, dp->ports[1].conf->hw_addr, ETH_ADDR_LEN);
	//le metemos el eth Type
	ofpbuf_put(buf, type_array, 2);
	//rellenamos
	ofpbuf_put(buf, Total, 45);
	/******Logica para evitar rebotes******/
	//rellenamos con la posicion que ocupa el switch
	if (dp->id < 100) //somos un ToR
		posicion = PORT_TOR;
	else if (dp->id >= 100 && dp->id < 1000) // somos un AgR
		posicion = PORT_AGR;
	else if (dp->id >= 1000)
		posicion = PORT_CORE; // somos un core
	ofpbuf_put(buf, &posicion, sizeof(posicion));
	/******FIN Logica para evitar rebotes******/
	//Creamos el buffer del paquete
	pkt = packet_create(dp, in_port, buf, packet_out);

	//creamos la cabecera eth y le metemos los valores que queremos
	pkt->handle_std->proto->eth = xmalloc(sizeof(struct eth_header));
	memcpy(pkt->handle_std->proto->eth->eth_dst, Mac, ETH_ADDR_LEN);
	memcpy(pkt->handle_std->proto->eth->eth_src, dp->ports[1].conf->hw_addr, ETH_ADDR_LEN);
	pkt->handle_std->proto->eth->eth_type = type;

	pkt->handle_std->valid = false;
	packet_handle_std_validate(pkt->handle_std);

    return pkt;
}


void packet_hello_send(void)
{
	dp_actions_output_port(pkt_hello_propio_aoss, OFPP_FLOOD, pkt_hello_propio_aoss->out_queue, pkt_hello_propio_aoss->out_port_max_len, 0xffffffffffffffff);
}

struct packet * packet_recovery_create(struct datapath *dp, uint32_t in_port, bool packet_out, struct packet * pkt_original, uint8_t opcion)
{
	struct packet *pkt = NULL;
	struct ofpbuf *buf = NULL;
	uint8_t Total[32], Mac[ETH_ADDR_LEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, Mac_origen[ETH_ADDR_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00}, 
		Mac_dst[ETH_ADDR_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00}, Mac_scr[ETH_ADDR_LEN] = {0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t op_array[2] = {0x00, 0x00}, type_array[2] = {0x00,0x00};
	uint16_t type = 0x0000;

	//Creamos el buffer del paquete
	buf = ofpbuf_new(sizeof(struct arppath_repair_header)); //sizeof(struct eth_header));
	//lo rellenamos con la broadcast
	ofpbuf_put(buf, Mac,ETH_ADDR_LEN);
	
	if (opcion == 1)
	{
		op_array[0] = 0x01; // es un recovery request
		type = ETH_TYPE_REPAIR_UAH;
		type_array[0] = 0x77;
		type_array[1] = 0x97;
		//lo rellenamos con la mac switch       
		memcpy(Mac_origen, dp->ports[1].conf->hw_addr, ETH_ADDR_LEN); //obtenemos Mac_src
		memcpy(Mac_dst, pkt_original->handle_std->proto->eth->eth_dst, ETH_ADDR_LEN); //obtenemos Mac_dst
		memcpy(Mac_scr, pkt_original->handle_std->proto->eth->eth_src, ETH_ADDR_LEN); //obtenemos Mac_dst
	}
	else
	{
		//log_uah("Opcion 2 detectada\n", dp->id);
		op_array[0] = 0x02; // es un recovery reply
		type = ETH_TYPE_ARPPATH_UAH;
		type_array[0] = 0x77;
		type_array[1] = 0x98;
		//obtenemos Mac_src (host a recuperar)
		memcpy(Mac_origen, ofpbuf_at(pkt_original->buffer, (pkt_original->buffer->size - ETH_ADDR_LEN - 32*sizeof(uint8_t)), ETH_ADDR_LEN), ETH_ADDR_LEN); 
		memcpy(Mac_scr, ofpbuf_at(pkt_original->buffer, (pkt_original->buffer->size - ETH_ADDR_LEN - 32*sizeof(uint8_t)), ETH_ADDR_LEN), ETH_ADDR_LEN); 
		memcpy(Mac_dst, ofpbuf_at(pkt_original->buffer, (pkt_original->buffer->size - 2*ETH_ADDR_LEN - 32*sizeof(uint8_t)), ETH_ADDR_LEN), ETH_ADDR_LEN); //obtenemos Mac_dst
	}
	//lo rellenamos con la mac switch       
	ofpbuf_put(buf, Mac_origen, ETH_ADDR_LEN);
	//le metemos el eth Type
	ofpbuf_put(buf, type_array, 2);
	//Parametros para la recuperacion
	//recovery_op
	ofpbuf_put(buf, op_array, 2);
	//recovery_mac_src
	ofpbuf_put(buf, Mac_scr, ETH_ADDR_LEN);
	//recovery_mac_dst
	ofpbuf_put(buf, Mac_dst, ETH_ADDR_LEN);
	//rellenamos para que sea un paquete completo
	ofpbuf_put(buf, Total, 32);

	//Creamos el buffer del paquete
	pkt = packet_create(dp, in_port, buf, packet_out);

	//creamos la cabecera eth y le metemos los valores que queremos
	pkt->handle_std->proto->eth = xmalloc(sizeof(struct eth_header));
	memcpy(pkt->handle_std->proto->eth->eth_dst, Mac, ETH_ADDR_LEN);
	memcpy(pkt->handle_std->proto->eth->eth_src, dp->ports[1].conf->hw_addr, ETH_ADDR_LEN);
	pkt->handle_std->proto->eth->eth_type = type;
	
	//creamos el paquete de recuperacion y metemos los valores
	pkt->handle_std->proto->arppath_repair = xmalloc(sizeof(struct arppath_repair_header));
	memcpy(pkt->handle_std->proto->arppath_repair->recovery_mac_src, pkt_original->handle_std->proto->eth->eth_src, ETH_ADDR_LEN);
	memcpy(pkt->handle_std->proto->arppath_repair->recovery_mac_dst, pkt_original->handle_std->proto->eth->eth_dst, ETH_ADDR_LEN);
	pkt->handle_std->proto->arppath_repair->recovery_op = ((uint16_t)op_array[1] << 8) | op_array[0];
	
	pkt->handle_std->valid = false;
	packet_handle_std_validate(pkt->handle_std);

    return pkt;
}

void send_packet_recovery(struct datapath *dp, struct packet * pkt_original, uint8_t opcion)
{
	struct packet *pkt = packet_recovery_create(dp, 0, 1, pkt_original, opcion); 
	dp_actions_output_port(pkt, OFPP_FLOOD, pkt->out_queue, pkt->out_port_max_len, 0xffffffffffffffff);
	packet_destroy(pkt);
}

struct packet * packet_Arppath_as_a_service_create(struct datapath *dp, uint32_t in_port, bool packet_out)
{
	struct packet *pkt = NULL;
	struct ofpbuf *buf = NULL;
	int i=0;
	uint8_t Total[45], Mac[ETH_ADDR_LEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF} , type_array[2] = {0xAA, 0xAA};
	uint16_t type = 0xAAAA;

	for (i=0; i<45; i++)
		Total[i]=0x00;
	
	//Creamos el buffer del paquete
	buf = ofpbuf_new(46); //sizeof(struct eth_header));
	//lo rellenamos con la broadcast
	ofpbuf_put(buf, Mac,ETH_ADDR_LEN);
	//lo rellenamos con la mac switch       
	ofpbuf_put(buf, dp->ports[1].conf->hw_addr, ETH_ADDR_LEN);
	//le metemos el eth Type
	ofpbuf_put(buf, type_array, 2);
	//insertamos las ID necesarias
	ofpbuf_put(buf, &dp->id, sizeof(uint64_t)); //id_switch original
	ofpbuf_put(buf, &dp->id, sizeof(uint64_t)); //id_switch actual, en este caso son iguales porque solo crean este paquete los switch fronteras (originales)
	//rellenamos
	ofpbuf_put(buf, Total, sizeof(Total));
	//Creamos el buffer del paquete
	pkt = packet_create(dp, in_port, buf, packet_out);

	//creamos la cabecera eth y le metemos los valores que queremos
	pkt->handle_std->proto->eth = xmalloc(sizeof(struct eth_header));
	memcpy(pkt->handle_std->proto->eth->eth_dst, Mac, ETH_ADDR_LEN);
	memcpy(pkt->handle_std->proto->eth->eth_src, dp->ports[1].conf->hw_addr, ETH_ADDR_LEN);
	pkt->handle_std->proto->eth->eth_type = type;

	pkt->handle_std->valid = false;
	packet_handle_std_validate(pkt->handle_std);

    return pkt;
}

void packet_arppath_as_a_service_send(void)
{
	dp_actions_output_port(pkt_arppath_as_service, OFPP_RANDOM, pkt_arppath_as_service->out_queue, pkt_arppath_as_service->out_port_max_len, 0xffffffffffffffff);
}