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
#include <time.h>
#include <sys/time.h>

#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>

#include "action_set.h"
#include "compiler.h"
#include "dp_actions.h"
#include "dp_buffers.h"
#include "dp_exp.h"
#include "dp_ports.h"
#include "datapath.h"
#include "packet.h"
#include "pipeline.h"
#include "flow_table.h"
#include "flow_entry.h"
#include "meter_table.h"
#include "oflib/ofl.h"
#include "oflib/ofl-structs.h"
#include "util.h"
#include "hash.h"
#include "oflib/oxm-match.h"
#include "vlog.h"

#define PUERTO_ELEFANTE 30000
#define TCP_PATH 0 //indicamos si queremos tcp path TCP_PATH = 0 -> arppath | TCP_PATH = 1 -> tcpppath | TCP_PATH = 2 tcppath for elefant
#define PATH_RECOVERY 0
#define controlador 0
#define recuperacion 0  //controlador activa el envio al controler y recuperacion activa recuperacion
#define RECOVERY_DIST 1 //indicamos si queremos recuperacion distribuida
#define BService_ARPPATH 3
#define BT_TIME 15
#define LT_TIME 300
#define TCP_TIME 10 //tiempo lt y bt

//modificacion uah
#include <pthread.h>
pthread_mutex_t pkt_tcp_syn = PTHREAD_MUTEX_INITIALIZER; //necesitamos bloquear el proceso mientras encapsulamos (dup)

float TIME_REC = 0.2;

#define LOG_MODULE VLM_pipeline

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static void
execute_entry(struct pipeline *pl, struct flow_entry *entry,
              struct flow_table **table, struct packet **pkt);

struct pipeline *
pipeline_create(struct datapath *dp) {
    struct pipeline *pl;
    int i;
    pl = xmalloc(sizeof(struct pipeline));
    for (i=0; i<PIPELINE_TABLES; i++) {
        pl->tables[i] = flow_table_create(dp, i);
    }
    pl->dp = dp;
    nblink_initialize();
    return pl;
}

static bool
is_table_miss(struct flow_entry *entry){
    return ((entry->stats->priority) == 0 && (entry->match->length <= 4));
}

/* Sends a packet to the controller in a packet_in message */
static void
send_packet_to_controller(struct pipeline *pl, struct packet *pkt, uint8_t table_id, uint8_t reason) {

    struct ofl_msg_packet_in msg;
    struct ofl_match *m;
    msg.header.type = OFPT_PACKET_IN;
    msg.total_len   = pkt->buffer->size;
    msg.reason      = reason;
    msg.table_id    = table_id;
    msg.cookie      = 0xffffffffffffffff;
    msg.data = pkt->buffer->data;


    /* A max_len of OFPCML_NO_BUFFER means that the complete
        packet should be sent, and it should not be buffered.*/
    if (pl->dp->config.miss_send_len != OFPCML_NO_BUFFER){
        dp_buffers_save(pl->dp->buffers, pkt);
        msg.buffer_id   = pkt->buffer_id;
        msg.data_length = MIN(pl->dp->config.miss_send_len, pkt->buffer->size);
    }else {
        msg.buffer_id   = OFP_NO_BUFFER;
        msg.data_length = pkt->buffer->size;
    }

    m = &pkt->handle_std->match;
    /* In this implementation the fields in_port and in_phy_port
        always will be the same, because we are not considering logical
        ports                                 */
    msg.match = (struct ofl_match_header*)m;
    dp_send_message(pl->dp, (struct ofl_msg_header *)&msg, NULL);
	ofl_structs_free_match((struct ofl_match_header* ) m, NULL);
}

static void
send_packet_to_controller_uah(struct pipeline *pl, struct packet *pkt, uint8_t table_id, uint8_t reason) {

    struct ofl_msg_packet_in msg;
    struct ofl_match *m;
    msg.header.type = OFPT_PACKET_IN;
    msg.total_len   = pkt->buffer->size;
    msg.reason      = reason;
    msg.table_id    = table_id;
    msg.cookie      = 0xffffffffffffffff;
    msg.data = pkt->buffer->data;


    /* A max_len of OFPCML_NO_BUFFER means that the complete
        packet should be sent, and it should not be buffered.*/
    if (pl->dp->config.miss_send_len != OFPCML_NO_BUFFER){
        dp_buffers_save(pl->dp->buffers, pkt);
        msg.buffer_id   = pkt->buffer_id;
        msg.data_length = MIN(pl->dp->config.miss_send_len, pkt->buffer->size);
    }else {
        msg.buffer_id   = OFP_NO_BUFFER;
        msg.data_length = pkt->buffer->size;
    }

    m = &pkt->handle_std->match;
    /* In this implementation the fields in_port and in_phy_port
        always will be the same, because we are not considering logical
        ports                                 */
    msg.match = (struct ofl_match_header*)m;
    dp_send_message(pl->dp, (struct ofl_msg_header *)&msg, NULL);
	//ofl_structs_free_match((struct ofl_match_header* ) m, NULL);
}

/* Pass the packet through the flow tables.
 * This function takes ownership of the packet and will destroy it. */
void
pipeline_process_packet(struct pipeline *pl, struct packet *pkt) {
    struct flow_table *table, *next_table;

    if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        char *pkt_str = packet_to_string(pkt);
        VLOG_DBG_RL(LOG_MODULE, &rl, "processing packet: %s", pkt_str);
        free(pkt_str);
    }

    if (!packet_handle_std_is_ttl_valid(pkt->handle_std)) {
        send_packet_to_controller(pl, pkt, 0/*table_id*/, OFPR_INVALID_TTL);
        packet_destroy(pkt);
        return;
    }

    next_table = pl->tables[0];
    while (next_table != NULL) {
        struct flow_entry *entry;

        VLOG_DBG_RL(LOG_MODULE, &rl, "trying table %u.", next_table->stats->table_id);

        pkt->table_id = next_table->stats->table_id;
        table         = next_table;
        next_table    = NULL;

        // EEDBEH: additional printout to debug table lookup
        if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
            char *m = ofl_structs_match_to_string((struct ofl_match_header*)&(pkt->handle_std->match), pkt->dp->exp);
            VLOG_DBG_RL(LOG_MODULE, &rl, "searching table entry for packet match: %s.", m);
            free(m);
        }
        entry = flow_table_lookup(table, pkt);
        if (entry != NULL) {
	        if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
                char *m = ofl_structs_flow_stats_to_string(entry->stats, pkt->dp->exp);
                VLOG_DBG_RL(LOG_MODULE, &rl, "found matching entry: %s.", m);
                free(m);
            }
            pkt->handle_std->table_miss = is_table_miss(entry);
            execute_entry(pl, entry, &next_table, &pkt);
            /* Packet could be destroyed by a meter instruction */
            if (!pkt)
                return;

            if (next_table == NULL) {
               /* Cookie field is set 0xffffffffffffffff
                because we cannot associate it to any
                particular flow */
                action_set_execute(pkt->action_set, pkt, 0xffffffffffffffff);
                return;
            }

        } else {
			/* OpenFlow 1.3 default behavior on a table miss */
			VLOG_DBG_RL(LOG_MODULE, &rl, "No matching entry found. Dropping packet.");
			packet_destroy(pkt);
			return;
        }
    }
    VLOG_WARN_RL(LOG_MODULE, &rl, "Reached outside of pipeline processing cycle.");
}

static
int inst_compare(const void *inst1, const void *inst2){
    struct ofl_instruction_header * i1 = *(struct ofl_instruction_header **) inst1;
    struct ofl_instruction_header * i2 = *(struct ofl_instruction_header **) inst2;
    if ((i1->type == OFPIT_APPLY_ACTIONS && i2->type == OFPIT_CLEAR_ACTIONS) ||
        (i1->type == OFPIT_CLEAR_ACTIONS && i2->type == OFPIT_APPLY_ACTIONS))
        return i1->type > i2->type;

    return i1->type < i2->type;
}

ofl_err
pipeline_handle_flow_mod(struct pipeline *pl, struct ofl_msg_flow_mod *msg,
                                                const struct sender *sender) {
    /* Note: the result of using table_id = 0xff is undefined in the spec.
     *       for now it is accepted for delete commands, meaning to delete
     *       from all tables */
    ofl_err error;
    size_t i;
    bool match_kept,insts_kept;

    if(sender->remote->role == OFPCR_ROLE_SLAVE)
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_IS_SLAVE);

    match_kept = false;
    insts_kept = false;

    /*Sort by execution oder*/
    qsort(msg->instructions, msg->instructions_num,
        sizeof(struct ofl_instruction_header *), inst_compare);

    // Validate actions in flow_mod
    for (i=0; i< msg->instructions_num; i++) {
        if (msg->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            msg->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)msg->instructions[i];

            error = dp_actions_validate(pl->dp, ia->actions_num, ia->actions);
            if (error) {
                return error;
            }
            error = dp_actions_check_set_field_req(msg, ia->actions_num, ia->actions);
            if (error) {
                return error;
            }
        }
	/* Reject goto in the last table. */
	if ((msg->table_id == (PIPELINE_TABLES - 1))
	    && (msg->instructions[i]->type == OFPIT_GOTO_TABLE))
	  return ofl_error(OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_INST);
    }

    if (msg->table_id == 0xff) {
        if (msg->command == OFPFC_DELETE || msg->command == OFPFC_DELETE_STRICT) {
            size_t i;

            error = 0;
            for (i=0; i < PIPELINE_TABLES; i++) {
                error = flow_table_flow_mod(pl->tables[i], msg, &match_kept, &insts_kept);
                if (error) {
                    break;
                }
            }
            if (error) {
                return error;
            } else {
                ofl_msg_free_flow_mod(msg, !match_kept, !insts_kept, pl->dp->exp);
                return 0;
            }
        } else {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_TABLE_ID);
        }
    } else {
        error = flow_table_flow_mod(pl->tables[msg->table_id], msg, &match_kept, &insts_kept);
        if (error) {
            return error;
        }
        if ((msg->command == OFPFC_ADD || msg->command == OFPFC_MODIFY || msg->command == OFPFC_MODIFY_STRICT) &&
                            msg->buffer_id != NO_BUFFER) {
            /* run buffered message through pipeline */
            struct packet *pkt;

            pkt = dp_buffers_retrieve(pl->dp->buffers, msg->buffer_id);
            if (pkt != NULL) {
		      pipeline_process_packet(pl, pkt);
            } else {
                VLOG_WARN_RL(LOG_MODULE, &rl, "The buffer flow_mod referred to was empty (%u).", msg->buffer_id);
            }
        }
		
        ofl_msg_free_flow_mod(msg, !match_kept, !insts_kept, pl->dp->exp);
        return 0;
    }

}

ofl_err
pipeline_handle_table_mod(struct pipeline *pl,
                          struct ofl_msg_table_mod *msg,
                          const struct sender *sender) {

    if(sender->remote->role == OFPCR_ROLE_SLAVE)
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_IS_SLAVE);

    if (msg->table_id == 0xff) {
        size_t i;

        for (i=0; i<PIPELINE_TABLES; i++) {
            pl->tables[i]->features->config = msg->config;
        }
    } else {
        pl->tables[msg->table_id]->features->config = msg->config;
    }

    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}

ofl_err
pipeline_handle_stats_request_flow(struct pipeline *pl,
                                   struct ofl_msg_multipart_request_flow *msg,
                                   const struct sender *sender) {

    struct ofl_flow_stats **stats = xmalloc(sizeof(struct ofl_flow_stats *));
    size_t stats_size = 1;
    size_t stats_num = 0;

    if (msg->table_id == 0xff) {
        size_t i;
        for (i=0; i<PIPELINE_TABLES; i++) {
            flow_table_stats(pl->tables[i], msg, &stats, &stats_size, &stats_num);
        }
    } else {
        flow_table_stats(pl->tables[msg->table_id], msg, &stats, &stats_size, &stats_num);
    }

    {
        struct ofl_msg_multipart_reply_flow reply =
                {{{.type = OFPT_MULTIPART_REPLY},
                  .type = OFPMP_FLOW, .flags = 0x0000},
                 .stats     = stats,
                 .stats_num = stats_num
                };

        dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);
    }

    free(stats);
    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}

ofl_err
pipeline_handle_stats_request_table(struct pipeline *pl,
                                    struct ofl_msg_multipart_request_header *msg UNUSED,
                                    const struct sender *sender) {
    struct ofl_table_stats **stats;
    size_t i;

    stats = xmalloc(sizeof(struct ofl_table_stats *) * PIPELINE_TABLES);

    for (i=0; i<PIPELINE_TABLES; i++) {
        stats[i] = pl->tables[i]->stats;
    }

    {
        struct ofl_msg_multipart_reply_table reply =
                {{{.type = OFPT_MULTIPART_REPLY},
                  .type = OFPMP_TABLE, .flags = 0x0000},
                 .stats     = stats,
                 .stats_num = PIPELINE_TABLES};

        dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);
    }

    free(stats);
    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}

ofl_err
pipeline_handle_stats_request_table_features_request(struct pipeline *pl,
                                    struct ofl_msg_multipart_request_header *msg,
                                    const struct sender *sender) {
    struct ofl_table_features **features;
    struct ofl_msg_multipart_request_table_features *feat =
                       (struct ofl_msg_multipart_request_table_features *) msg;
    int i;           /* Feature index in feature array. Jean II */
    int table_id;
    ofl_err error = 0;

    /* Further validation of request not done in
     * ofl_structs_table_features_unpack(). Jean II */
    if(feat->table_features != NULL) {
        for(i = 0; i < feat->tables_num; i++){
	    if(feat->table_features[i]->table_id >= PIPELINE_TABLES)
	        return ofl_error(OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_TABLE);
	    /* We may want to validate things like config, max_entries,
	     * metadata... */
        }
    }

    /* Check if we already received fragments of a multipart request. */
    if(sender->remote->mp_req_msg != NULL) {
      bool nomore;

      /* We can only merge requests having the same XID. */
      if(sender->xid != sender->remote->mp_req_xid)
	{
	  VLOG_ERR(LOG_MODULE, "multipart request: wrong xid (0x%X != 0x%X)", sender->xid, sender->remote->mp_req_xid);

	  /* Technically, as our buffer can only hold one pending request,
	   * this is a buffer overflow ! Jean II */
	  /* Return error. */
	  return ofl_error(OFPET_BAD_REQUEST, OFPBRC_MULTIPART_BUFFER_OVERFLOW);
	}

      VLOG_DBG(LOG_MODULE, "multipart request: merging with previous fragments (%zu+%zu)", ((struct ofl_msg_multipart_request_table_features *) sender->remote->mp_req_msg)->tables_num, feat->tables_num);

      /* Merge the request with previous fragments. */
      nomore = ofl_msg_merge_multipart_request_table_features((struct ofl_msg_multipart_request_table_features *) sender->remote->mp_req_msg, feat);

      /* Check if incomplete. */
      if(!nomore)
	return 0;

      VLOG_DBG(LOG_MODULE, "multipart request: reassembly complete (%zu)", ((struct ofl_msg_multipart_request_table_features *) sender->remote->mp_req_msg)->tables_num);

      /* Use the complete request. */
      feat = (struct ofl_msg_multipart_request_table_features *) sender->remote->mp_req_msg;

#if 0
      {
	char *str;
	str = ofl_msg_to_string((struct ofl_msg_header *) feat, pl->dp->exp);
	VLOG_DBG(LOG_MODULE, "\nMerged request:\n%s\n\n", str);
	free(str);
      }
#endif

    } else {
      /* Check if the request is an initial fragment. */
      if(msg->flags & OFPMPF_REQ_MORE) {
	struct ofl_msg_multipart_request_table_features* saved_msg;

	VLOG_DBG(LOG_MODULE, "multipart request: create reassembly buffer (%zu)", feat->tables_num);

	/* Create a buffer the do reassembly. */
	saved_msg = (struct ofl_msg_multipart_request_table_features*) malloc(sizeof(struct ofl_msg_multipart_request_table_features));
	saved_msg->header.header.type = OFPT_MULTIPART_REQUEST;
	saved_msg->header.type = OFPMP_TABLE_FEATURES;
	saved_msg->header.flags = 0;
	saved_msg->tables_num = 0;
	saved_msg->table_features = NULL;

	/* Save the fragment for later use. */
	ofl_msg_merge_multipart_request_table_features(saved_msg, feat);
	sender->remote->mp_req_msg = (struct ofl_msg_multipart_request_header *) saved_msg;
	sender->remote->mp_req_xid = sender->xid;

	return 0;
      }

      /* Non fragmented request. Nothing to do... */
      VLOG_DBG(LOG_MODULE, "multipart request: non-fragmented request (%zu)", feat->tables_num);
    }

    /*Check to see if the body is empty.*/
    /* Should check merge->tables_num instead. Jean II */
    if(feat->table_features != NULL){
        int last_table_id = 0;

	/* Check that the table features make sense. */
        for(i = 0; i < feat->tables_num; i++){
            /* Table-IDs must be in ascending order. */
            table_id = feat->table_features[i]->table_id;
            if(table_id < last_table_id) {
                error = ofl_error(OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_TABLE);
		break;
            }
            /* Can't go over out internal max-entries. */
            if (feat->table_features[i]->max_entries > FLOW_TABLE_MAX_ENTRIES) {
                error = ofl_error(OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_ARGUMENT);
		break;
            }
        }

        if (error == 0) {

            /* Disable all tables, they will be selectively re-enabled. */
            for(table_id = 0; table_id < PIPELINE_TABLES; table_id++){
	        pl->tables[table_id]->disabled = true;
            }
            /* Change tables configuration
               TODO: Remove flows*/
            VLOG_DBG(LOG_MODULE, "pipeline_handle_stats_request_table_features_request: updating features");
            for(i = 0; i < feat->tables_num; i++){
                table_id = feat->table_features[i]->table_id;

                /* Replace whole table feature. */
                ofl_structs_free_table_features(pl->tables[table_id]->features, pl->dp->exp);
                pl->tables[table_id]->features = feat->table_features[i];
                feat->table_features[i] = NULL;

                /* Re-enable table. */
                pl->tables[table_id]->disabled = false;
            }
        }
    }

    /* Cleanup request. */
    if(sender->remote->mp_req_msg != NULL) {
      ofl_msg_free((struct ofl_msg_header *) sender->remote->mp_req_msg, pl->dp->exp);
      sender->remote->mp_req_msg = NULL;
      sender->remote->mp_req_xid = 0;  /* Currently not needed. Jean II. */
    }

    if (error) {
        return error;
    }

    table_id = 0;
    /* Query for table capabilities */
    loop: ;
    features = (struct ofl_table_features**) xmalloc(sizeof(struct ofl_table_features *) * 8);
    /* Return 8 tables per reply segment. */
    for (i = 0; i < 8; i++){
        /* Skip disabled tables. */
        while((table_id < PIPELINE_TABLES) && (pl->tables[table_id]->disabled == true))
	    table_id++;
	/* Stop at the last table. */
	if(table_id >= PIPELINE_TABLES)
	    break;
	/* Use that table in the reply. */
        features[i] = pl->tables[table_id]->features;
        table_id++;
    }
    VLOG_DBG(LOG_MODULE, "multipart reply: returning %d tables, next table-id %d", i, table_id);
    {
    struct ofl_msg_multipart_reply_table_features reply =
         {{{.type = OFPT_MULTIPART_REPLY},
           .type = OFPMP_TABLE_FEATURES,
           .flags = (table_id == PIPELINE_TABLES ? 0x00000000 : OFPMPF_REPLY_MORE) },
          .table_features     = features,
          .tables_num = i };
          dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);
    }
    if (table_id < PIPELINE_TABLES){
           goto loop;
    }
    free(features);

    return 0;
}

ofl_err
pipeline_handle_stats_request_aggregate(struct pipeline *pl,
                                  struct ofl_msg_multipart_request_flow *msg,
                                  const struct sender *sender) {
    struct ofl_msg_multipart_reply_aggregate reply =
            {{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_AGGREGATE, .flags = 0x0000},
              .packet_count = 0,
              .byte_count   = 0,
              .flow_count   = 0};

    if (msg->table_id == 0xff) {
        size_t i;

        for (i=0; i<PIPELINE_TABLES; i++) {
            flow_table_aggregate_stats(pl->tables[i], msg,
                                       &reply.packet_count, &reply.byte_count, &reply.flow_count);
        }

    } else {
        flow_table_aggregate_stats(pl->tables[msg->table_id], msg,
                                   &reply.packet_count, &reply.byte_count, &reply.flow_count);
    }

    dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);

    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}


void
pipeline_destroy(struct pipeline *pl) {
    struct flow_table *table;
    int i;

    for (i=0; i<PIPELINE_TABLES; i++) {
        table = pl->tables[i];
        if (table != NULL) {
            flow_table_destroy(table);
        }
    }
    free(pl);
}


void
pipeline_timeout(struct pipeline *pl) {
    int i;

    for (i = 0; i < PIPELINE_TABLES; i++) {
        flow_table_timeout(pl->tables[i]);
    }
}


/* Executes the instructions associated with a flow entry */
static void
execute_entry(struct pipeline *pl, struct flow_entry *entry,
              struct flow_table **next_table, struct packet **pkt) {
    /* NOTE: instructions, when present, will be executed in
            the following order:
            Meter
            Apply-Actions
            Clear-Actions
            Write-Actions
            Write-Metadata
            Goto-Table
    */
    size_t i;
    struct ofl_instruction_header *inst;

    for (i=0; i < entry->stats->instructions_num; i++) {
        /*Packet was dropped by some instruction or action*/

        if(!(*pkt)){
            return;
        }

        inst = entry->stats->instructions[i];
        switch (inst->type) {
            case OFPIT_GOTO_TABLE: {
                struct ofl_instruction_goto_table *gi = (struct ofl_instruction_goto_table *)inst;

                *next_table = pl->tables[gi->table_id];
                break;
            }
            case OFPIT_WRITE_METADATA: {
                struct ofl_instruction_write_metadata *wi = (struct ofl_instruction_write_metadata *)inst;
                struct  ofl_match_tlv *f;

                /* NOTE: Hackish solution. If packet had multiple handles, metadata
                 *       should be updated in all. */
                packet_handle_std_validate((*pkt)->handle_std);
                /* Search field on the description of the packet. */
                HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv,
                    hmap_node, hash_int(OXM_OF_METADATA,0), &(*pkt)->handle_std->match.match_fields){
                    uint64_t *metadata = (uint64_t*) f->value;
                    *metadata = (*metadata & ~wi->metadata_mask) | (wi->metadata & wi->metadata_mask);
                    VLOG_DBG_RL(LOG_MODULE, &rl, "Executing write metadata: %"PRIu64"", *metadata);
                }
                break;
            }
            case OFPIT_WRITE_ACTIONS: {
                struct ofl_instruction_actions *wa = (struct ofl_instruction_actions *)inst;
                action_set_write_actions((*pkt)->action_set, wa->actions_num, wa->actions);
                break;
            }
            case OFPIT_APPLY_ACTIONS: {
                struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)inst;
                dp_execute_action_list((*pkt), ia->actions_num, ia->actions, entry->stats->cookie);
                break;
            }
            case OFPIT_CLEAR_ACTIONS: {
                action_set_clear_actions((*pkt)->action_set);
                break;
            }
            case OFPIT_METER: {
            	struct ofl_instruction_meter *im = (struct ofl_instruction_meter *)inst;
                meter_table_apply(pl->dp->meters, pkt , im->meter_id);
                break;
            }
            case OFPIT_EXPERIMENTER: {
                dp_exp_inst((*pkt), (struct ofl_instruction_experimenter *)inst);
                break;
            }
        }
    }
}
void
pipeline_process_Uah(struct pipeline *pl, struct packet *pkt, struct mac_to_port *mac_port, 
struct mac_to_port *recovery_table, uint8_t *puerto_no_disponible, struct timeval * t_ini_recuperacion)
{
	struct flow_table *table, *next_table;
	struct packet *pkt_to_contro = NULL;
	//int enviar_por_arp_path = 2;
	int TIME_RECOVERY = 1;
	
	//int puerto_mac = 0;
	struct timeval t_fin_recuperacion; //para la toma de medidas de recuperacion
	//char Texto[50]; //texto para recuperacion
	//double tiempo_recuperacion;
	
	if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        char *pkt_str = packet_to_string(pkt);
        VLOG_DBG_RL(LOG_MODULE, &rl, "processing packet: %s", pkt_str);
        free(pkt_str);
    }

    if (!packet_handle_std_is_ttl_valid(pkt->handle_std)) {
        send_packet_to_controller(pl, pkt, 0/*table_id*/, OFPR_INVALID_TTL);
        packet_destroy(pkt);
        return;
    }
	if(pkt->handle_std->proto->eth->eth_type == 30360 ||
			pkt->handle_std->proto->eth->eth_type == 39030) //packet hello
	{
		//pasamos a realizar la actualizacion de la tabla de vecinos
		if(mac_to_port_found_port(&neighbor_table, pkt->handle_std->proto->eth->eth_src) != -1)
			mac_to_port_update(&neighbor_table, pkt->handle_std->proto->eth->eth_src, pkt->in_port, TIME_RECOVERY);
		else
			mac_to_port_add_hello(&neighbor_table, pkt, pkt->in_port, TIME_RECOVERY);
		//una vez recopilado el mensaje envio al controlador
		packet_destroy(pkt);
		return;
	}
	//introducimos la nueva logica para arppath as a service
	if(pkt->handle_std->proto->eth->eth_type == 0xAAAA)
	{
		//copiamos el paquete original para asi poder lanzarlo al controlador despues (recordamos que tenemos que colorearlo)
		pkt_to_contro = packet_clone(pkt);
		//Necesitamos copiar el paquete que recibimos para poder hacer la doble via (propagar por la red y enviar al controller)
		if(mac_to_port_found_port(&Arppath_as_a_service_table, pkt->handle_std->proto->eth->eth_src) != -1) //si existe
		{
			//indicamos que no es el primero
			indicar_posicion_ptk_arppath_as_a_service(pkt_to_contro, 2);
			packet_destroy(pkt);
		}
		else
		{
			//Indicamos que es el primer paquete enviado al controler
			indicar_posicion_ptk_arppath_as_a_service(pkt_to_contro, 1);
			mac_to_port_add_arp_table(&Arppath_as_a_service_table, pkt->handle_std->proto->eth->eth_src, pkt->in_port, BService_ARPPATH, pkt);
			modificar_nuevo_switch_arppath_as_a_service(pkt, pkt->dp->id);
			//enviamos por todos los puertos ya que es un broadcast
			dp_actions_output_port(pkt, OFPP_RANDOM, pkt->out_queue, pkt->out_port_max_len, 0xffffffffffffffff);
			//destruimos el paquete enviado
			if (pkt != NULL)
				packet_destroy(pkt);
		}
		//enviamos el paquete recibido al controller
		send_packet_to_controller_uah(pl, pkt_to_contro, 0, OFPR_NO_MATCH);
		if (pkt_to_contro != NULL)
			packet_destroy(pkt_to_contro);
		return; //salimos
	}
	next_table = pl->tables[0];
	while (next_table != NULL)
	{
        struct flow_entry *entry;

        VLOG_DBG_RL(LOG_MODULE, &rl, "trying table %u.", next_table->stats->table_id);

        pkt->table_id = next_table->stats->table_id;
        table         = next_table;
        next_table    = NULL;
		
        // EEDBEH: additional printout to debug table lookup
        if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
            char *m = ofl_structs_match_to_string((struct ofl_match_header*)&(pkt->handle_std->match), pkt->dp->exp);
            VLOG_DBG_RL(LOG_MODULE, &rl, "searching table entry for packet match: %s.", m);
            free(m);
        }
        entry = flow_table_lookup(table, pkt);
        if (entry != NULL) {
			if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
                char *m = ofl_structs_flow_stats_to_string(entry->stats, pkt->dp->exp);
                VLOG_DBG_RL(LOG_MODULE, &rl, "found matching entry: %s.", m);
                free(m);
            }
			//medimos en el caso de fallo anterior en arppath
			if (recuperacion == 1 && *(puerto_no_disponible) == 1)
			{
				gettimeofday(&t_fin_recuperacion, NULL);
				*(puerto_no_disponible) = 2;
			}
			pkt->handle_std->table_miss = is_table_miss(entry);
			execute_entry(pl, entry, &next_table, &pkt);
			/* Packet could be destroyed by a meter instruction */
            if (!pkt)
                return;
            if (next_table == NULL) {
               /* Cookie field is set 0xffffffffffffffff
                because we cannot associate it to any
                particular flow */
                action_set_execute(pkt->action_set, pkt, 0xffffffffffffffff);
                return;
            }
		}
	}
	if(pkt->handle_std->proto->eth->eth_type == 56710) //eliminamos icmpv6
	{
		packet_destroy(pkt);
		return ;
	}
	pipeline_arp_path(pl, pkt, mac_port, recovery_table, TIME_RECOVERY, puerto_no_disponible, t_ini_recuperacion);
	return;
}

void pipeline_arp_path(struct pipeline *pl, struct packet *pkt, struct mac_to_port *mac_port,
          struct mac_to_port *recovery_table, int TIME_RECOVERY, uint8_t * puerto_no_disponible, struct timeval * t_ini_recuperacion)
{
        int puerto_mac = 0; //varible auxiliar para puertp
        struct packet *pkt_to_contro = NULL;

		//solo clonamos si es ARP
		if (controlador == 1 && (pkt->handle_std->proto->eth->eth_type == 1544 || pkt->handle_std->proto->arppath != NULL)) 
			pkt_to_contro = packet_clone(pkt);
		
        puerto_mac = mac_to_port_found_port(mac_port, pkt->handle_std->proto->eth->eth_src);
        //Comprobar si BroadCast o Multicast
        if (eth_addr_is_broadcast(pkt->handle_std->proto->eth->eth_dst) || eth_addr_is_multicast(pkt->handle_std->proto->eth->eth_dst))
        {
			if (puerto_mac == -1)
				mac_to_port_add_arp_table(mac_port, pkt->handle_std->proto->eth->eth_src, pkt->in_port, BT_TIME, pkt);
			else if (puerto_mac == pkt->in_port)
				mac_to_port_time_refresh(mac_port, pkt->handle_std->proto->eth->eth_src, BT_TIME);
			else if (mac_to_port_check_timeout(mac_port, pkt->handle_std->proto->eth->eth_src) != 0)
				mac_to_port_update(mac_port, pkt->handle_std->proto->eth->eth_src, pkt->in_port, BT_TIME);
			else
			{
				packet_destroy(pkt); //destruimos paquete
				return;
			}
			dp_actions_output_port(pkt, OFPP_RANDOM, pkt->out_queue, pkt->out_port_max_len, 0xffffffffffffffff);
        }
        else //trafic unicast
        {
            //es arp_reply, no tenemos flujo
			if(pkt->handle_std->proto->eth->eth_type == 1544 || pkt->handle_std->proto->arppath != NULL)
			{
				//LLega paquete ARP REPLY hay que encapsular
				if(pkt->handle_std->proto->arp != NULL)
				{
					if ((pkt->handle_std->proto->arp->ar_op/256) == 2 && puerto_mac == -1)
						mac_to_port_add_arp_table(mac_port, pkt->handle_std->proto->eth->eth_src, pkt->in_port, LT_TIME, pkt);
					else if ((pkt->handle_std->proto->arp->ar_op/256) == 2)
					{
						if(mac_to_port_check_timeout(mac_port, pkt->handle_std->proto->eth->eth_src) == 1)
							mac_to_port_update(mac_port, pkt->handle_std->proto->eth->eth_src, pkt->in_port, LT_TIME);
						else
							mac_to_port_time_refresh(mac_port, pkt->handle_std->proto->eth->eth_src,LT_TIME); //actuliza time
					}
				}
				else if (pkt->handle_std->proto->arppath != NULL) //el paquete llega encapsulado
				{
					if(puerto_mac == -1)
						mac_to_port_add_arp_table(mac_port, pkt->handle_std->proto->eth->eth_src, pkt->in_port, LT_TIME, pkt);
					else
					{
						if(mac_to_port_check_timeout(mac_port, pkt->handle_std->proto->eth->eth_src) == 1)
							mac_to_port_update(mac_port, pkt->handle_std->proto->eth->eth_src, pkt->in_port, LT_TIME);
						else
							mac_to_port_time_refresh(mac_port, pkt->handle_std->proto->eth->eth_src,LT_TIME);
					}
				}
			}
			puerto_mac = mac_to_port_found_port(mac_port, pkt->handle_std->proto->eth->eth_dst);
			arp_path_send_unicast(pl, pkt, mac_port, recovery_table, TIME_RECOVERY, puerto_mac, puerto_no_disponible, t_ini_recuperacion);
        }
         if(pkt_to_contro != NULL )
        {
			send_macs_to_ctr(pl, pkt_to_contro);
        }
        return;
}

int arp_path_send_unicast(struct pipeline * pl, struct packet * pkt, struct mac_to_port * mac_port,
        struct mac_to_port * recovery_table, int TIME_RECOVERY, int out_port, uint8_t * puerto_no_disponible, struct timeval * t_ini_recuperacion)
{
	struct timeval t_fin_recuperacion; //para la toma de medidas de recuperacion
	//double tiempo_recuperacion;
	
	//antes debemos comprobar si el 
	if (out_port != -1) //si existe puerto de salida
	{
		//visualizar_tabla(mac_port, pkt->dp->id);
		//hemos terminado con el paquete, desbloqueamos
		if(recuperacion == 0 || pkt->dp->ports[out_port].conf->state == OFPPS_LIVE)
		{
			if (recuperacion == 1 && (*puerto_no_disponible) == 1)
			{
				gettimeofday(&t_fin_recuperacion, NULL);
				*(puerto_no_disponible) = 2;
			}
			//actualizamos LT siempre que reenviamos
			mac_to_port_time_refresh(mac_port, pkt->handle_std->proto->eth->eth_dst,LT_TIME);
			dp_actions_output_port(pkt,out_port,pkt->out_queue, pkt->out_port_max_len, 0xffffffffffffffff);
		}
		else if (recuperacion == 1)
		{
 			if (*(puerto_no_disponible) == 0)
			{
				//cogemos tiempo
				gettimeofday(t_ini_recuperacion, NULL);
				*(puerto_no_disponible) = 1; //indicamos el puerto no esta disponible para poder medir con precision
			}
			//comprobamos que no tengamos una recuperacion ya iniciada
			if( mac_to_port_check_timeout(recovery_table, pkt->handle_std->proto->eth->eth_dst) != 0)
			{
				mac_to_port_add(recovery_table, pkt->handle_std->proto->eth->eth_dst, pkt->in_port, TIME_RECOVERY);
				mac_to_port_delete_port(mac_port, out_port);
				if (RECOVERY_DIST == 0) //si no queremos la distribuida
					send_packet_to_controller_uah(pl, pkt, 0, OFPR_NO_MATCH);
				else
					send_packet_recovery(pl->dp, pkt, 1); //path recovery (buscamos switch destino)
			} 
		}
	}
	else if(recuperacion == 1)//por lo menos tener una referencia del flujo
	{
 		if (*(puerto_no_disponible) == 0)
		{
			//cogemos tiempo
			gettimeofday(t_ini_recuperacion, NULL);
			*(puerto_no_disponible) = 1; //indicamos el puerto no esta disponible para poder medir con precision
		}
		//inicamos la reparacion si no la tenemos ya iniciada
		if(mac_to_port_check_timeout(recovery_table, pkt->handle_std->proto->eth->eth_dst) != 0)
		{
			mac_to_port_add(recovery_table, pkt->handle_std->proto->eth->eth_dst, pkt->in_port, TIME_RECOVERY);
			if (RECOVERY_DIST == 0) //si no queremos la distribuida
				send_packet_to_controller_uah(pl, pkt, 0, OFPR_NO_MATCH);
			else
				send_packet_recovery(pl->dp, pkt, 1); //path recovery (buscamos switch destino)
		}
	}
	return 0;
}


int send_macs_to_ctr(struct pipeline *pl, struct packet *pkt)
{
	pkt->handle_std->proto->eth->eth_type = 30360;
	//pkt_to_contro->handle_std->proto->eth->eth_type = 0x7698; //usamos el mismo codigo que los hellos
	if (is_neighbor(pkt) != 1)
		return -1; //no lo enviamos
	else
	{
		send_packet_to_controller_uah(pl, pkt, 0, OFPR_ACTION); //mandamos la que esta aunque sea repetida
		return 0;
	}
}

double timeval_diff_uah(struct timeval *a, struct timeval *b)
{
  return
    (double)(((double)a->tv_sec)*1000000 + (double)(a->tv_usec)) -
    (double)(((double)b->tv_sec)*1000000 + (double)(b->tv_usec));
}

int Found_date_in_pkt(int codigo, int busqueda, struct packet * pkt )
{
	uint16_t puerto = 0; //, i;
	//ahora empieza la parte de adquisicion real del dato
	struct ofl_match_header * match = (struct ofl_match_header *)(&pkt->handle_std->match);
	//obtener puerto 
	struct ofl_match_tlv *f ;

	f = oxm_match_lookup(all_fields[codigo].header, (struct ofl_match*) match);
	if (f != NULL) 
	{
		if (OXM_FIELD(f->header) == busqueda)
		{
			puerto = *((uint16_t*) f->value);
			return (int)puerto;
		}
	}
	return -1;
}
