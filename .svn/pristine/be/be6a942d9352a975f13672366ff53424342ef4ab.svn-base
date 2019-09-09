/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

/* The original Stanford code has been modified during the implementation of
 * the OpenFlow 1.1 userspace switch.
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include "dp_exp.h"
#include "dp_ports.h"
#include "datapath.h"
#include "packets.h"
#include "pipeline.h"
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"
#include "oflib-exp/ofl-exp-openflow.h"
#include "oflib/ofl-log.h"
#include "util.h"

#include "vlog.h"
#define LOG_MODULE VLM_dp_ports

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

#if defined(OF_HW_PLAT)
#include <openflow/of_hw_api.h>
#include <pthread.h>
#endif


#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
/* Queue to decouple receive packet thread from rconn control thread */
/* Could make mutex per-DP */
static pthread_mutex_t pkt_q_mutex = PTHREAD_MUTEX_INITIALIZER;
#define PKT_Q_LOCK pthread_mutex_lock(&pkt_q_mutex)
#define PKT_Q_UNLOCK pthread_mutex_unlock(&pkt_q_mutex)

static void
enqueue_pkt(struct datapath *dp, struct ofpbuf *buffer, of_port_t port_no,
            int reason)
{
    struct hw_pkt_q_entry *q_entry;

    if ((q_entry = xmalloc(sizeof(*q_entry))) == NULL) {
        VLOG_WARN(LOG_MODULE, "Could not alloc q entry\n");
        /* FIXME: Dealloc buffer */
        return;
    }
    q_entry->buffer = buffer;
    q_entry->next = NULL;
    q_entry->port_no = port_no;
    q_entry->reason = reason;
    pthread_mutex_lock(&pkt_q_mutex);
    if (dp->hw_pkt_list_head == NULL) {
        dp->hw_pkt_list_head = q_entry;
    } else {
        dp->hw_pkt_list_tail->next = q_entry;
    }
    dp->hw_pkt_list_tail = q_entry;
    pthread_mutex_unlock(&pkt_q_mutex);
}

/* If queue non-empty, fill out params and return 1; else return 0 */
static int
dequeue_pkt(struct datapath *dp, struct ofpbuf **buffer, of_port_t *port_no,
            int *reason)
{
    struct hw_pkt_q_entry *q_entry;
    int rv = 0;

    pthread_mutex_lock(&pkt_q_mutex);
    q_entry = dp->hw_pkt_list_head;
    if (dp->hw_pkt_list_head != NULL) {
        dp->hw_pkt_list_head = dp->hw_pkt_list_head->next;
        if (dp->hw_pkt_list_head == NULL) {
            dp->hw_pkt_list_tail = NULL;
        }
    }
    pthread_mutex_unlock(&pkt_q_mutex);

    if (q_entry != NULL) {
        rv = 1;
        *buffer = q_entry->buffer;
        *port_no = q_entry->port_no;
        *reason = q_entry->reason;
        free(q_entry);
    }

    return rv;
}
#endif


/* FIXME: Should not depend on udatapath_as_lib */
#if defined(OF_HW_PLAT) && !defined(USE_NETDEV) && defined(UDATAPATH_AS_LIB)
/*
 * Receive packet handling for hardware driver controlled ports
 *
 * FIXME:  For now, call the pkt fwding directly; eventually may
 * want to enqueue packets at this layer; at that point must
 * make sure poll event is registered or timer kicked
 */
static int
hw_packet_in(of_port_t port_no, of_packet_t *packet, int reason,
             void *cookie)
{
    struct sw_port *port;
    struct ofpbuf *buffer = NULL;
    struct datapath *dp = (struct datapath *)cookie;
    const int headroom = 128 + 2;
    const int hard_header = VLAN_ETH_HEADER_LEN;
    const int tail_room = sizeof(uint32_t);  /* For crc if needed later */

    VLOG_INFO(LOG_MODULE, "dp rcv packet on port %d, size %d\n",
              port_no, packet->length);
    if ((port_no < 1) || port_no > DP_MAX_PORTS) {
        VLOG_ERR(LOG_MODULE, "Bad receive port %d\n", port_no);
        /* TODO increment error counter */
        return -1;
    }
    port = &dp->ports[port_no];
    if (!PORT_IN_USE(port)) {
        VLOG_WARN(LOG_MODULE, "Receive port not active: %d\n", port_no);
        return -1;
    }
    if (!IS_HW_PORT(port)) {
        VLOG_ERR(LOG_MODULE, "Receive port not controlled by HW: %d\n", port_no);
        return -1;
    }
    /* Note:  We're really not counting these for port stats as they
     * should be gotten directly from the HW */
    port->rx_packets++;
    port->rx_bytes += packet->length;
    /* For now, copy data into OFP buffer; eventually may steal packet
     * from RX to avoid copy.  As per dp_run, add headroom and offset bytes.
     */
    buffer = ofpbuf_new(headroom + hard_header + packet->length + tail_room);
    if (buffer == NULL) {
        VLOG_WARN(LOG_MODULE, "Could not alloc ofpbuf on hw pkt in\n");
        fprintf(stderr, "Could not alloc ofpbuf on hw pkt in\n");
    } else {
        buffer->data = (char*)buffer->data + headroom;
        buffer->size = packet->length;
        memcpy(buffer->data, packet->data, packet->length);
        enqueue_pkt(dp, buffer, port_no, reason);
        poll_immediate_wake();
    }

    return 0;
}
#endif

#if defined(OF_HW_PLAT)
static int
dp_hw_drv_init(struct datapath *dp)
{
    dp->hw_pkt_list_head = NULL;
    dp->hw_pkt_list_tail = NULL;

    dp->hw_drv = new_of_hw_driver(dp);
    if (dp->hw_drv == NULL) {
        VLOG_ERR(LOG_MODULE, "Could not create HW driver");
        return -1;
    }
#if !defined(USE_NETDEV)
    if (dp->hw_drv->packet_receive_register(dp->hw_drv,
                                            hw_packet_in, dp) < 0) {
        VLOG_ERR(LOG_MODULE, "Could not register with HW driver to receive pkts");
    }
#endif

    return 0;
}

#endif


/* Runs a datapath packet through the pipeline, if the port is not set to down. */
static void
process_buffer(struct datapath *dp, struct sw_port *p, struct ofpbuf *buffer, struct mac_to_port *mac_port, struct mac_to_port *recovery_table, uint8_t *puerto_no_disponible, struct timeval * t_ini_recuperacion){
    struct packet *pkt;

    if (p->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN) != 0)) {
        ofpbuf_delete(buffer);
        return;
    }

    // packet takes ownership of ofpbuf buffer
    pkt = packet_create(dp, p->stats->port_no, buffer, false);
    //pipeline_process_packet(dp->pipeline, pkt);
    pipeline_process_Uah(dp->pipeline, pkt, mac_port, recovery_table, puerto_no_disponible, t_ini_recuperacion); //modificacion UAH
}

void
dp_ports_run(struct datapath *dp, struct mac_to_port *mac_port,  struct mac_to_port *recovery_table, uint8_t *puerto_no_disponible, struct timeval * t_ini_recuperacion) {
    // static, so an unused buffer can be reused at the dp_ports_run call
    static struct ofpbuf *buffer = NULL;
    int max_mtu = 0;

    struct sw_port *p, *pn;

#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
    { /* Process packets received from callback thread */
        struct ofpbuf *buffer;
        of_port_t port_no;
        int reason;
        struct sw_port *p;

        while (dequeue_pkt(dp, &buffer, &port_no, &reason)) {
            p = dp_ports_lookup(dp, port_no);
            /* FIXME:  We're throwing away the reason that came from HW */
            process_packet(dp, p, buffer);
        }
    }
#endif
    // find largest MTU on our interfaces
    // buffer is shared among all (idle) interfaces...
    LIST_FOR_EACH_SAFE (p, pn, struct sw_port, node, &dp->port_list) {        
        const int mtu = netdev_get_mtu(p->netdev);
        if (IS_HW_PORT(p)) 
            continue;
        if (mtu > max_mtu)
            max_mtu = mtu;
    }

	
    LIST_FOR_EACH_SAFE (p, pn, struct sw_port, node, &dp->port_list) {
        int error;
        /* Check for interface state change */
        enum netdev_link_state link_state = netdev_link_state(p->netdev);
        if (link_state == NETDEV_LINK_UP){
            p->conf->state &= ~OFPPS_LINK_DOWN;
            dp_port_live_update(p);
        }
        else if (link_state == NETDEV_LINK_DOWN){
            p->conf->state |= OFPPS_LINK_DOWN;
            dp_port_live_update(p);
        }

        if (IS_HW_PORT(p)) {
            continue;
        }
        if (buffer == NULL) {
            /* Allocate buffer with some headroom to add headers in forwarding
             * to the controller or adding a vlan tag, plus an extra 2 bytes to
             * allow IP headers to be aligned on a 4-byte boundary.  */
            const int headroom = 128 + 2;
            buffer = ofpbuf_new_with_headroom(VLAN_ETH_HEADER_LEN + max_mtu, headroom);
        }
        error = netdev_recv(p->netdev, buffer, VLAN_ETH_HEADER_LEN + max_mtu);
        if (!error) {
            p->stats->rx_packets++;
            p->stats->rx_bytes += buffer->size;
            // process_buffer takes ownership of ofpbuf buffer
            process_buffer(dp, p, buffer, mac_port,recovery_table, puerto_no_disponible, t_ini_recuperacion); 
			//modificacion uah
            buffer = NULL;
        } else if (error != EAGAIN) {
            VLOG_ERR_RL(LOG_MODULE, &rl, "error receiving data from %s: %s",
                        netdev_get_name(p->netdev), strerror(error));
        }
    }
}

/* Returns the speed value in kbps of the highest bit set in the bitfield. */
static uint32_t port_speed(uint32_t conf) {
    if ((conf & OFPPF_1TB_FD) != 0)   return 1024 * 1024 * 1024;
    if ((conf & OFPPF_100GB_FD) != 0) return  100 * 1024 * 1024;
    if ((conf & OFPPF_40GB_FD) != 0)  return   40 * 1024 * 1024;
    if ((conf & OFPPF_10GB_FD) != 0)  return   10 * 1024 * 1024;
    if ((conf & OFPPF_1GB_FD) != 0)   return        1024 * 1024;
    if ((conf & OFPPF_1GB_HD) != 0)   return        1024 * 1024;
    if ((conf & OFPPF_100MB_FD) != 0) return         100 * 1024;
    if ((conf & OFPPF_100MB_HD) != 0) return         100 * 1024;
    if ((conf & OFPPF_10MB_FD) != 0)  return          10 * 1024;
    if ((conf & OFPPF_10MB_HD) != 0)  return          10 * 1024;

    return 0;
}

/* Creates a new port, with queues. */
static int
new_port(struct datapath *dp, struct sw_port *port, uint32_t port_no,
         const char *netdev_name, const uint8_t *new_mac, uint32_t max_queues)
{
    struct netdev *netdev;
    struct in6_addr in6;
    struct in_addr in4;
    int error;
    uint64_t now;

    now = time_msec();

    max_queues = MIN(max_queues, NETDEV_MAX_QUEUES);

    error = netdev_open(netdev_name, NETDEV_ETH_TYPE_ANY, &netdev);
    if (error) {
        return error;
    }
    if (new_mac && !eth_addr_equals(netdev_get_etheraddr(netdev), new_mac)) {
        /* Generally the device has to be down before we change its hardware
         * address.  Don't bother to check for an error because it's really
         * the netdev_set_etheraddr() call below that we care about. */
        netdev_set_flags(netdev, 0, false);
        error = netdev_set_etheraddr(netdev, new_mac);
        if (error) {
            VLOG_WARN(LOG_MODULE, "failed to change %s Ethernet address "
                      "to "ETH_ADDR_FMT": %s",
                      netdev_name, ETH_ADDR_ARGS(new_mac), strerror(error));
        }
    }
    error = netdev_set_flags(netdev, NETDEV_UP | NETDEV_PROMISC, false);
    if (error) {
        VLOG_ERR(LOG_MODULE, "failed to set promiscuous mode on %s device", netdev_name);
        netdev_close(netdev);
        return error;
    }
    if (netdev_get_in4(netdev, &in4)) {
        VLOG_ERR(LOG_MODULE, "%s device has assigned IP address %s",
                 netdev_name, inet_ntoa(in4));
    }
    if (netdev_get_in6(netdev, &in6)) {
        char in6_name[INET6_ADDRSTRLEN + 1];
        inet_ntop(AF_INET6, &in6, in6_name, sizeof in6_name);
        VLOG_ERR(LOG_MODULE, "%s device has assigned IPv6 address %s",
                 netdev_name, in6_name);
    }

    if (max_queues > 0) {
        error = netdev_setup_slicing(netdev, max_queues);
        if (error) {
            VLOG_ERR(LOG_MODULE, "failed to configure slicing on %s device: "\
                     "check INSTALL for dependencies, or rerun "\
                     "using --no-slicing option to disable slicing",
                     netdev_name);
            netdev_close(netdev);
            return error;
        }
    }

    /* NOTE: port struct is already allocated in struct dp */
    memset(port, '\0', sizeof *port);

    port->dp = dp;

    port->conf = xmalloc(sizeof(struct ofl_port));
    port->conf->port_no    = port_no;
    memcpy(port->conf->hw_addr, netdev_get_etheraddr(netdev), ETH_ADDR_LEN);
    port->conf->name       = strcpy(xmalloc(strlen(netdev_name) + 1), netdev_name);
    port->conf->config     = 0x00000000;
    port->conf->state      = 0x00000000 | OFPPS_LIVE;
    port->conf->curr       = netdev_get_features(netdev, NETDEV_FEAT_CURRENT);
    port->conf->advertised = netdev_get_features(netdev, NETDEV_FEAT_ADVERTISED);
    port->conf->supported  = netdev_get_features(netdev, NETDEV_FEAT_SUPPORTED);
    port->conf->peer       = netdev_get_features(netdev, NETDEV_FEAT_PEER);
    port->conf->curr_speed = port_speed(port->conf->curr);
    port->conf->max_speed  = port_speed(port->conf->supported);

    if (IS_HW_PORT(p)) {
#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
        of_hw_driver_t *hw_drv;

        hw_drv = p->dp->hw_drv;
        free(port->conf->name);
        port->conf->name = strcpy(xmalloc(strlen(p->hw_name) + 1), p->hw_name);
        / * Update local port state * /
        if (hw_drv->port_link_get(hw_drv, port_no)) {
            p->state &= ~OFPPS_LINK_DOWN;
        } else {
            p->state |= OFPPS_LINK_DOWN;
        }
        if (hw_drv->port_enable_get(hw_drv, port_no)) {
            p->config &= ~OFPPC_PORT_DOWN;
        } else {
            p->config |= OFPPC_PORT_DOWN;
        }
        / * FIXME:  Add current, supported and advertised features * /
#endif
    }
    dp_port_live_update(port);

    port->stats = xmalloc(sizeof(struct ofl_port_stats));
    port->stats->port_no = port_no;
    port->stats->rx_packets   = 0;
    port->stats->tx_packets   = 0;
    port->stats->rx_bytes     = 0;
    port->stats->tx_bytes     = 0;
    port->stats->rx_dropped   = 0;
    port->stats->tx_dropped   = 0;
    port->stats->rx_errors    = 0;
    port->stats->tx_errors    = 0;
    port->stats->rx_frame_err = 0;
    port->stats->rx_over_err  = 0;
    port->stats->rx_crc_err   = 0;
    port->stats->collisions   = 0;
    port->stats->duration_sec = 0;
    port->stats->duration_nsec = 0;
    port->flags |= SWP_USED;
    port->netdev = netdev;
    port->max_queues = max_queues;
    port->num_queues = 0;
    port->created = now;

    memset(port->queues, 0x00, sizeof(port->queues));

    list_push_back(&dp->port_list, &port->node);
    dp->ports_num++;

    {
    /* Notify the controllers that this port has been added */
    struct ofl_msg_port_status msg =
            {{.type = OFPT_PORT_STATUS},
             .reason = OFPPR_ADD, .desc = port->conf};

        dp_send_message(dp, (struct ofl_msg_header *)&msg, NULL/*sender*/);
    }

    return 0;
}


#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
int
dp_ports_add(struct datapath *dp, const char *port_name)
{
    int port_no;
    int rc = 0;
    struct sw_port *port;

    fprintf(stderr, "Adding port %s. hw_drv is %p\n", port_name, dp->hw_drv);
    if (dp->hw_drv && dp->hw_drv->port_add) {
        port_no = dp->hw_drv->port_add(dp->hw_drv, -1, port_name);
        if (port_no >= 0) {
            port = &dp->ports[port_no];
            if (port->flags & SWP_USED) {
                VLOG_ERR(LOG_MODULE, "HW port %s (%d) already created\n",
                          port_name, port_no);
                rc = -1;
            } else {
                fprintf(stderr, "Adding HW port %s as OF port number %d\n",
                       port_name, port_no);
                /* FIXME: Determine and record HW addr, etc */
                port->flags |= SWP_USED | SWP_HW_DRV_PORT;
                port->dp = dp;
                port->port_no = port_no;
                list_init(&port->queue_list);
                port->max_queues = max_queues;
                port->num_queues = 0;
                strncpy(port->hw_name, port_name, sizeof(port->hw_name));
                list_push_back(&dp->port_list, &port->node);

                struct ofl_msg_port_status msg =
                        {{.type = OFPT_PORT_STATUS},
                         .reason = OFPPR_ADD, .desc = p->conf};

                dp_send_message(dp, (struct ofl_msg_header *)&msg, NULL);

            }
        } else {
            VLOG_ERR(LOG_MODULE, "Port %s not recognized by hardware driver", port_name);
            rc = -1;
        }
    } else {
        VLOG_ERR(LOG_MODULE, "No hardware driver support; can't add ports");
        rc = -1;
    }

    return rc;
}
#else /* Not HW platform support */

int
dp_ports_add(struct datapath *dp, const char *netdev)
{
    uint32_t port_no;
    for (port_no = 1; port_no < DP_MAX_PORTS; port_no++) {
        struct sw_port *port = &dp->ports[port_no];
        if (port->netdev == NULL) {
            return new_port(dp, port, port_no, netdev, NULL, dp->max_queues);
        }
    }
    return EXFULL;
}
#endif /* OF_HW_PLAT */

int
dp_ports_add_local(struct datapath *dp, const char *netdev)
{
    if (!dp->local_port) {
        uint8_t ea[ETH_ADDR_LEN];
        struct sw_port *port;
        int error;

        port = xcalloc(1, sizeof *port);
        eth_addr_from_uint64(dp->id, ea);
        error = new_port(dp, port, OFPP_LOCAL, netdev, ea, 0);
        if (!error) {
            dp->local_port = port;
        } else {
            free(port);
        }
        return error;
    } else {
        return EXFULL;
    }
}


struct sw_port *
dp_ports_lookup(struct datapath *dp, uint32_t port_no) {

    // exclude local port from ports_num
    uint32_t ports_num = dp->local_port ? dp->ports_num -1 : dp->ports_num;

    if (port_no == OFPP_LOCAL) {
        return dp->local_port;
    }
    /* Local port already checked, so dp->ports -1 */
    if (port_no < 1 || port_no > ports_num) {
        return NULL;
    }

    return &dp->ports[port_no];
}

struct sw_queue *
dp_ports_lookup_queue(struct sw_port *p, uint32_t queue_id)
{
    struct sw_queue *q;

    if (queue_id < p->max_queues) {
        q = &(p->queues[queue_id]);

        if (q->port != NULL) {
            return q;
        }
    }

    return NULL;
}

void
dp_ports_output(struct datapath *dp, struct ofpbuf *buffer, uint32_t out_port,
              uint32_t queue_id)
{
    uint16_t class_id;
    struct sw_queue * q;
    struct sw_port *p;

    p = dp_ports_lookup(dp, out_port);

    /* FIXME:  Needs update for queuing */
    #if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
    if ((p != NULL) && IS_HW_PORT(p)) {
        if (dp && dp->hw_drv) {
            if (dp->hw_drv->port_link_get(dp->hw_drv, p->port_no)) {
                of_packet_t *pkt;
                int rv;

                pkt = calloc(1, sizeof(*pkt));
                OF_PKT_INIT(pkt, buffer);
                rv = dp->hw_drv->packet_send(dp->hw_drv, out_port, pkt, 0);
                if ((rv < 0) && (rv != OF_HW_PORT_DOWN)) {
                    VLOG_ERR(LOG_MODULE, "Error %d sending pkt on HW port %d\n",
                             rv, out_port);
                    ofpbuf_delete(buffer);
                    free(pkt);
                }
            }
        }
        return;
    }

    /* Fall through to software controlled ports if not HW port */
	#endif
    if (p != NULL && p->netdev != NULL) {
        if (!(p->conf->config & OFPPC_PORT_DOWN)) {
            /* avoid the queue lookup for best-effort traffic */
            if (queue_id == 0) {
                q = NULL;
                class_id = 0;
            }
            else {
                /* silently drop the packet if queue doesn't exist */
                q = dp_ports_lookup_queue(p, queue_id);
                if (q != NULL) {
                    class_id = q->class_id;
                }
                else {
                    goto error;
                }
            }

            if (!netdev_send(p->netdev, buffer, class_id)) {
                p->stats->tx_packets++;
                p->stats->tx_bytes += buffer->size;
                if (q != NULL) {
                    q->stats->tx_packets++;
                    q->stats->tx_bytes += buffer->size;
                }
            } else {
                p->stats->tx_dropped++;
            }
        }
        /* NOTE: no need to delete buffer, it is deleted along with the packet in caller. */
        return;
    }

 error:
     /* NOTE: no need to delete buffer, it is deleted along with the packet. */
    VLOG_DBG_RL(LOG_MODULE, &rl, "can't forward to bad port:queue(%d:%d)\n", out_port,
                queue_id);
}

int
dp_ports_output_all(struct datapath *dp, struct ofpbuf *buffer, int in_port, bool flood)
{
    struct sw_port *p;

    LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list) {
        if (p->stats->port_no == in_port) {
            continue;
        }
        if (flood && p->conf->config & OFPPC_NO_FWD) {
            continue;
        }
        dp_ports_output(dp, buffer, p->stats->port_no, 0);
    }

    return 0;
}

ofl_err
dp_ports_handle_port_mod(struct datapath *dp, struct ofl_msg_port_mod *msg,
                                                const struct sender *sender) {

    struct sw_port *p;
    struct ofl_msg_port_status rep_msg;

    if(sender->remote->role == OFPCR_ROLE_SLAVE)
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_IS_SLAVE);

    p = dp_ports_lookup(dp, msg->port_no);

    if (p == NULL) {
        return ofl_error(OFPET_PORT_MOD_FAILED,OFPPMFC_BAD_PORT);
    }

    /* Make sure the port id hasn't changed since this was sent */
    if (memcmp(msg->hw_addr, netdev_get_etheraddr(p->netdev),
                     ETH_ADDR_LEN) != 0) {
        return ofl_error(OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_HW_ADDR);
    }


    if (msg->mask) {
        p->conf->config &= ~msg->mask;
        p->conf->config |= msg->config & msg->mask;
        dp_port_live_update(p);
    }

    /*Notify all controllers that the port status has changed*/
    rep_msg.header.type = OFPT_PORT_STATUS;
    rep_msg.reason =   OFPPR_MODIFY;
    rep_msg.desc = p->conf;      
    dp_send_message(dp, (struct ofl_msg_header *)&rep_msg, NULL/*sender*/);
    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

static void
dp_port_stats_update(struct sw_port *port) {
    port->stats->duration_sec  =  (time_msec() - port->created) / 1000;
    port->stats->duration_nsec = ((time_msec() - port->created) % 1000) * 1000000;
}

void
dp_port_live_update(struct sw_port *p) {

  if((p->conf->state & OFPPS_LINK_DOWN)
     || (p->conf->config & OFPPC_PORT_DOWN)) {
      /* Port not live */
      p->conf->state &= ~OFPPS_LIVE;
  } else {
      /* Port is live */
      p->conf->state |= OFPPS_LIVE;
  }
}

ofl_err
dp_ports_handle_stats_request_port(struct datapath *dp,
                                  struct ofl_msg_multipart_request_port *msg,
                                  const struct sender *sender UNUSED) {
    struct sw_port *port;

    struct ofl_msg_multipart_reply_port reply =
            {{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_PORT_STATS, .flags = 0x0000},
             .stats_num   = 0,
             .stats       = NULL};

    if (msg->port_no == OFPP_ANY) {
        size_t i = 0;

        reply.stats_num = dp->ports_num;
        reply.stats     = xmalloc(sizeof(struct ofl_port_stats *) * dp->ports_num);

        LIST_FOR_EACH(port, struct sw_port, node, &dp->port_list) {
            dp_port_stats_update(port);
            reply.stats[i] = port->stats;
            i++;
        }

    } else {
        port = dp_ports_lookup(dp, msg->port_no);

        if (port != NULL && port->netdev != NULL) {
            reply.stats_num = 1;
            reply.stats = xmalloc(sizeof(struct ofl_port_stats *));
            dp_port_stats_update(port);
            reply.stats[0] = port->stats;
        }
    }

    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

    free(reply.stats);
    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);

    return 0;
}

ofl_err
dp_ports_handle_port_desc_request(struct datapath *dp,
                                  struct ofl_msg_multipart_request_header *msg UNUSED,
                                  const struct sender *sender UNUSED){
    struct sw_port *port;
    size_t i = 0;


    struct ofl_msg_multipart_reply_port_desc reply =
            {{{.type = OFPT_MULTIPART_REPLY},
             .type = OFPMP_PORT_DESC, .flags = 0x0000},
             .stats_num   = 0,
             .stats       = NULL};

    reply.stats_num = dp->ports_num;
    reply.stats     = xmalloc(sizeof(struct ofl_port *) * dp->ports_num);

    LIST_FOR_EACH(port, struct sw_port, node, &dp->port_list) {
        reply.stats[i] = port->conf;
        i++;
    }

    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

    free(reply.stats);
    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);

    return 0;
}

static void
dp_ports_queue_update(struct sw_queue *queue) {
    queue->stats->duration_sec  =  (time_msec() - queue->created) / 1000;
    queue->stats->duration_nsec = ((time_msec() - queue->created) % 1000) * 1000000;
}

ofl_err
dp_ports_handle_stats_request_queue(struct datapath *dp,
                                  struct ofl_msg_multipart_request_queue *msg,
                                  const struct sender *sender) {
    struct sw_port *port;

    struct ofl_msg_multipart_reply_queue reply =
            {{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_QUEUE, .flags = 0x0000},
             .stats_num   = 0,
             .stats       = NULL};

    if (msg->port_no == OFPP_ANY) {
        size_t i,idx = 0, num = 0;

        LIST_FOR_EACH(port, struct sw_port, node, &dp->port_list) {
            if (msg->queue_id == OFPQ_ALL) {
                num += port->num_queues;
            } else {
                if (msg->queue_id < port->max_queues) {
                    if (port->queues[msg->queue_id].port != NULL) {
                        num++;
                    }
                }
            }
        }

        reply.stats_num = num;
        reply.stats     = xmalloc(sizeof(struct ofl_port_stats *) * num);

        LIST_FOR_EACH(port, struct sw_port, node, &dp->port_list) {
            if (msg->queue_id == OFPQ_ALL) {
                for(i=0; i<port->max_queues; i++) {
                    if (port->queues[i].port != NULL) {
                        dp_ports_queue_update(&port->queues[i]);
                        reply.stats[idx] = port->queues[i].stats;
                        idx++;
                    }
                }
            } else {
                if (msg->queue_id < port->max_queues) {
                    if (port->queues[msg->queue_id].port != NULL) {
                        dp_ports_queue_update(&port->queues[msg->queue_id]);
                        reply.stats[idx] = port->queues[msg->queue_id].stats;
                        idx++;
                    }
                }
            }
        }

    } else {
        port = dp_ports_lookup(dp, msg->port_no);

        if (port != NULL && port->netdev != NULL) {
            size_t i, idx = 0;

            if (msg->queue_id == OFPQ_ALL) {
                reply.stats_num = port->num_queues;
                reply.stats = xmalloc(sizeof(struct ofl_port_stats *) * port->num_queues);

                for(i=0; i<port->max_queues; i++) {
                    if (port->queues[i].port != NULL) {
                        dp_ports_queue_update(&port->queues[i]);
                        reply.stats[idx] = port->queues[i].stats;
                        idx++;
                    }
                }
            } else {
                if (msg->queue_id < port->max_queues) {
                    if (port->queues[msg->queue_id].port != NULL) {
                        reply.stats_num = 1;
                        reply.stats = xmalloc(sizeof(struct ofl_port_stats *));
                        dp_ports_queue_update(&port->queues[msg->queue_id]);
                        reply.stats[0] = port->queues[msg->queue_id].stats;
                    }
                }
            }
        }
    }

    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

    free(reply.stats);
    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);

    return 0;
}

ofl_err
dp_ports_handle_queue_get_config_request(struct datapath *dp,
                              struct ofl_msg_queue_get_config_request *msg,
                                                const struct sender *sender) {
    struct sw_port *p;

    struct ofl_msg_queue_get_config_reply reply =
            {{.type = OFPT_QUEUE_GET_CONFIG_REPLY},
             .queues = NULL};

    if (msg->port == OFPP_ANY) {
        size_t i, idx = 0, num = 0;

        LIST_FOR_EACH(p, struct sw_port, node, &dp->port_list) {
            num += p->num_queues;
        }

        reply.port       = OFPP_ANY;
        reply.queues_num = num;
        reply.queues     = xmalloc(sizeof(struct ofl_packet_queue *) * num);

        LIST_FOR_EACH(p, struct sw_port, node, &dp->port_list) {
            for (i=0; i<p->max_queues; i++) {
                if (p->queues[i].port != NULL) {
                    reply.queues[idx] = p->queues[i].props;
                    idx++;
                }
             }
         }
    } else {
        p = dp_ports_lookup(dp, msg->port);

        if (p == NULL || (p->stats->port_no != msg->port)) {
            free(reply.queues);
            ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
            return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
        } else {
            size_t i, idx = 0;

            reply.port       = msg->port;
            reply.queues_num = p->num_queues;
            reply.queues     = xmalloc(sizeof(struct ofl_packet_queue *) * p->num_queues);

            for (i=0; i<p->max_queues; i++) {
                if (p->queues[i].port != NULL) {
                    reply.queues[idx] = p->queues[i].props;
                    idx++;
                }
            }
        }
    }

    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

    free(reply.queues);
    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

/*
 * Queue handling
 */

static int
new_queue(struct sw_port * port, struct sw_queue * queue,
          uint32_t queue_id, uint16_t class_id,
          struct ofl_queue_prop_min_rate * mr)
{
    uint64_t now = time_msec();

    memset(queue, '\0', sizeof *queue);
    queue->port = port;
    queue->created = now;
    queue->stats = xmalloc(sizeof(struct ofl_queue_stats));

    queue->stats->port_no = port->stats->port_no;
    queue->stats->queue_id = queue_id;
    queue->stats->tx_bytes = 0;
    queue->stats->tx_packets = 0;
    queue->stats->tx_errors = 0;
    queue->stats->duration_sec = 0;
    queue->stats->duration_nsec = 0;

    /* class_id is the internal mapping to class. It is the offset
     * in the array of queues for each port. Note that class_id is
     * local to port, so we don't have any conflict.
     * tc uses 16-bit class_id, so we cannot use the queue_id
     * field */
    queue->class_id = class_id;

    queue->props = xmalloc(sizeof(struct ofl_packet_queue));
    queue->props->queue_id = queue_id;
    queue->props->properties = xmalloc(sizeof(struct ofl_queue_prop_header *));
    queue->props->properties_num = 1;
    queue->props->properties[0] = xmalloc(sizeof(struct ofl_queue_prop_min_rate));
    ((struct ofl_queue_prop_min_rate *)(queue->props->properties[0]))->header.type = OFPQT_MIN_RATE;
    ((struct ofl_queue_prop_min_rate *)(queue->props->properties[0]))->rate = mr->rate;

    port->num_queues++;
    return 0;
}

static int
port_add_queue(struct sw_port *p, uint32_t queue_id,
               struct ofl_queue_prop_min_rate * mr)
{
    if (queue_id >= p->max_queues) {
        return EXFULL;
    }

    if (p->queues[queue_id].port != NULL) {
        return EXFULL;
    }

    return new_queue(p, &(p->queues[queue_id]), queue_id, queue_id, mr);
}

static int
port_delete_queue(struct sw_port *p, struct sw_queue *q)
{
    memset(q,'\0', sizeof *q);
    p->num_queues--;
    return 0;
}

ofl_err
dp_ports_handle_queue_modify(struct datapath *dp, struct ofl_exp_openflow_msg_queue *msg,
        const struct sender *sender UNUSED) {
    // NOTE: assumes the packet queue has exactly one property, for min rate
    struct sw_port *p;
    struct sw_queue *q;

    int error = 0;

    p = dp_ports_lookup(dp, msg->port_id);
    if (PORT_IN_USE(p)) {
        q = dp_ports_lookup_queue(p, msg->queue->queue_id);
        if (q != NULL) {
            /* queue exists - modify it */
            error = netdev_change_class(p->netdev,q->class_id,
                                 ((struct ofl_queue_prop_min_rate *)msg->queue->properties[0])->rate);
             if (error) {
                 VLOG_ERR(LOG_MODULE, "Failed to update queue %d", msg->queue->queue_id);
                 return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_EPERM);
             }
             else {
                 ((struct ofl_queue_prop_min_rate *)q->props->properties[0])->rate =
                         ((struct ofl_queue_prop_min_rate *)msg->queue->properties[0])->rate;
             }

        } else {
            /* create new queue */
            error = port_add_queue(p, msg->queue->queue_id,
                                       (struct ofl_queue_prop_min_rate *)msg->queue->properties[0]);
            if (error == EXFULL) {
                return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_EPERM);
            }

            q = dp_ports_lookup_queue(p, msg->queue->queue_id);
                error = netdev_setup_class(p->netdev,q->class_id,
                                ((struct ofl_queue_prop_min_rate *)msg->queue->properties[0])->rate);
                if (error) {
                    VLOG_ERR(LOG_MODULE, "Failed to configure queue %d", msg->queue->queue_id);
                    return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_QUEUE);
                }
        }

    } else {
        VLOG_ERR(LOG_MODULE, "Failed to create/modify queue - port %d doesn't exist", msg->port_id);
        return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
    }

    if (IS_HW_PORT(p)) {
#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
        error = dp->hw_drv->port_queue_config(dp->hw_drv, port_no,
                                              queue_id, ntohs(mr->rate));
        if (error < 0) {
            VLOG_ERR(LOG_MODULE, "Failed to update HW port %d queue %d",
                     port_no, queue_id);
        }
#endif
    }

    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}


ofl_err
dp_ports_handle_queue_delete(struct datapath *dp, struct ofl_exp_openflow_msg_queue *msg,
                                                  const struct sender *sender UNUSED) {
    struct sw_port *p;
    struct sw_queue *q;

    p = dp_ports_lookup(dp, msg->port_id);
    if (p != NULL && p->netdev != NULL) {
        q = dp_ports_lookup_queue(p, msg->queue->queue_id);
        if (q != NULL) {
            netdev_delete_class(p->netdev,q->class_id);
            port_delete_queue(p, q);

            ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
            return 0;
        } else {
            return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_QUEUE);
        }
    }

    return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
}

/*Modificacion uah funciones mac_to_port */

int
dp_ports_output_random(struct datapath *dp, struct ofpbuf *buffer, int in_port, bool flood, struct packet * pkt)
{
	//aleatorizamos la salida
	int i, port, num_matriz=(rand()%16);

	//generate random numbers:
	for (i=0;i<dp->ports_num;i++)
	{
		//cogemos el puerto
		port = Matriz_bc[num_matriz][i];
		if (port == 0) // || port == in_port) 
			continue;
		if (flood && (dp->ports[port].conf->config & OFPPC_NO_FWD)) 
			continue; 
		if (pkt->handle_std->proto->eth->eth_type == 0xAAAA)
		{
			if (port == in_port) insertar_outport_pkt(pkt, in_port);
			else insertar_outport_pkt(pkt, port);
			dp_ports_output(dp, pkt->buffer, port, 0); //salgo por todos los puertos sin distincion
		}
		else
			dp_ports_output(dp, buffer, port, 0); //salgo por todos los puertos sin distincion
	}
    return 0;
}


uint8_t tipo_switch_port(int port)
{
	struct mac_port_time *aux = neighbor_table.inicio;
	//uint64_t marca_tiempo_msec = time_msec();
	
	while(aux != NULL)
	{
		if(aux->port_in == port) // && marca_tiempo_msec < aux->time_entry)
			return aux->vecino; //puerto switch detectado
		aux = aux->next; //pasamos al siguiente elemento de la lista
	}
	return 0;//no se encontro el puerto, es un host
}

void mac_to_port_new(struct mac_to_port *mac_port)
{
	mac_port->inicio = NULL;
	mac_port->fin = NULL;
	mac_port->num_element = 0;
}

int mac_to_port_add_hello(struct mac_to_port *mac_port, struct packet *pkt, uint16_t port_in, int time)
{
	struct mac_port_time *nuevo_elemento = NULL;
	struct mac_port_time *actual = mac_port->fin;

	if ((nuevo_elemento = xmalloc (sizeof (struct mac_port_time))) == NULL)
		return -1;

	nuevo_elemento->port_in = port_in;
	nuevo_elemento->time_entry = time_msec() + time * 1000;
	memcpy(nuevo_elemento->Mac, pkt->handle_std->proto->eth->eth_src, ETH_ADDR_LEN);
	//guardamos el valor del vecino
	memcpy(&(nuevo_elemento->vecino), ofpbuf_at_assert(pkt->buffer, pkt->buffer->size - sizeof(uint8_t) , sizeof(uint8_t)), sizeof(uint8_t));
	nuevo_elemento->next = NULL;

	if(mac_port->inicio == NULL)
		mac_port->inicio = nuevo_elemento;
	else
		actual->next = nuevo_elemento;

	mac_port->fin = nuevo_elemento;
	mac_port->num_element++;
	return 0;
}

int mac_to_port_add(struct mac_to_port *mac_port, uint8_t Mac[ETH_ADDR_LEN], uint16_t port_in, int time)
{
	struct mac_port_time *nuevo_elemento = NULL;
	struct mac_port_time *actual = mac_port->fin;

	if ((nuevo_elemento = xmalloc (sizeof (struct mac_port_time))) == NULL)
		return -1;

	nuevo_elemento->port_in = port_in;
	nuevo_elemento->time_entry = time_msec() + time * 1000;
	memcpy(nuevo_elemento->Mac, Mac, ETH_ADDR_LEN);
	//guardamos el valor del vecino
	nuevo_elemento->vecino = 0;
	nuevo_elemento->next = NULL;

	if(mac_port->inicio == NULL)
		mac_port->inicio = nuevo_elemento;
	else
		actual->next = nuevo_elemento;

	mac_port->fin = nuevo_elemento;
	mac_port->num_element++;
	return 0;
}

int mac_to_port_add_arp_table(struct mac_to_port *mac_port, uint8_t Mac[ETH_ADDR_LEN],  uint16_t port_in, int time, struct packet * pkt)
{
	struct mac_port_time *nuevo_elemento = NULL;
	struct mac_port_time *actual = mac_port->inicio;

	if ((nuevo_elemento = xmalloc (sizeof (struct mac_port_time))) == NULL)
		return -1;

	nuevo_elemento->port_in = port_in;
	nuevo_elemento->time_entry = time_msec() + (time * 1000);
	memcpy(nuevo_elemento->Mac, Mac, ETH_ADDR_LEN);
	//comprobamos si es mi vecino o no
	nuevo_elemento->vecino = is_neighbor(pkt);
	
	if(mac_port->num_element == 0)
	{
		mac_port->fin = nuevo_elemento; //si no existen elementos el primero y el ultimo son el mismo
		nuevo_elemento->next = NULL; //si es el primero de la lista debe apuntar a null su siguiente elemento
	}
	else
		//colocamos el elemento al comienzo
		nuevo_elemento->next = actual;
	//colocamos al comienzo de la lista el elemento
	mac_port->inicio= nuevo_elemento;
	mac_port->num_element++;
	return 0;
}

int mac_to_port_update(struct mac_to_port *mac_port, uint8_t Mac[ETH_ADDR_LEN], uint16_t port_in, int time) //update element
{
	struct mac_port_time *aux = mac_port->inicio;
	uint64_t marca_tiempo_msec = time_msec() + (time * 1000);
	
	while(aux != NULL)
	{
		if(memcmp(aux->Mac, Mac, ETH_ADDR_LEN) == 0)
		{
			aux->port_in = port_in;
			//miramos cual si el tiempo guardado + la actualizacion
			if (marca_tiempo_msec > aux->time_entry)
				aux->time_entry = marca_tiempo_msec; // le metemos el tiempo correspondiente
			return 0; //todo correcto
		}
		aux = aux->next; //pasamos al siguiente elemento de la lista
	}
	return 1;//no se encontro la mac
}

int mac_to_port_time_refresh(struct mac_to_port *mac_port, uint8_t Mac[ETH_ADDR_LEN], uint64_t time) //update element
{
	struct mac_port_time *aux = mac_port->inicio;
	uint64_t marca_tiempo_msec = time_msec() + (time * 1000);
	
	while(aux != NULL)
	{
		if(memcmp(aux->Mac, Mac, ETH_ADDR_LEN) == 0)
		{
			//miramos cual si el tiempo guardado + la actualizacion
			if (marca_tiempo_msec > aux->time_entry)
				aux->time_entry = marca_tiempo_msec; // le metemos el tiempo correspondiente
			return 0; //todo correcto
		}
		aux = aux->next; //pasamos al siguiente elemento de la lista
	}
	return -1;//no se encontro la mac
}


int mac_to_port_found_port(struct mac_to_port *mac_port, uint8_t Mac[ETH_ADDR_LEN])
//chequemos si existe una mac y devolvemos un puerto
{
	struct mac_port_time *aux = mac_port->inicio, *ant = mac_port->inicio;
	uint64_t marca_tiempo_msec = time_msec();
	int pos = 1, port_select = -1;
	
	while(aux != NULL)
	{
		if((memcmp(aux->Mac, Mac, ETH_ADDR_LEN) == 0) && ((marca_tiempo_msec < aux->time_entry) || aux->vecino == 1) )
		{
			port_select = aux->port_in; //todo correcto
			break;
		}
		//anterior pasa a ser el actual
		ant = aux;
		//actual pasa a ser el siguiente
		aux = aux->next;
		pos++;
	}

	//si estamos lejos del comienzo de busqueda lo subimos // 
	if (pos > 2 && port_select > 0)
	{
		//1º como tenemos seleccionado el que vamos a mover, rearmamos la fila
		ant->next = aux->next;
		if(ant->next == NULL) // si no existe elemento siguiente, entonces somos el ultimo
			mac_port->fin = ant; //modificamos al elemento anterior para que sea el ultimo
		aux->next = mac_port->inicio; //enlazamos el antiguo 1º al nuevo 
		mac_port->inicio = aux; //colocamos el elemento encontrado como primero
	}
	
	
	return port_select; //si no existe tal puerto
}

int mac_to_port_check_timeout(struct mac_to_port *mac_port, uint8_t Mac[ETH_ADDR_LEN])
{
	struct mac_port_time *aux = mac_port->inicio;
	uint64_t marca_tiempo_msec = time_msec();
	//buscamos la relacion 
	while(aux != NULL)
	{
		if (memcmp(aux->Mac, Mac, ETH_ADDR_LEN) == 0)
		{
			if (marca_tiempo_msec > aux->time_entry && aux->vecino == 0) //mseg -> me devuelve en milisegundos
				return 1; // si hemos superado el tiempo de bloqueo
			else
				return 0; //si no se ha superado el tiempo de bloqueo
			}
		aux = aux->next;
	}
	return 2; //no existe la pareja mac -> port_in
}

int mac_to_port_delete_timeout(struct mac_to_port *mac_port)
{
	struct mac_port_time *aux = mac_port->inicio;
	struct mac_port_time *actual = mac_port->inicio;
	uint64_t marca_tiempo_msec = time_msec();
	
	while (actual != NULL)
	{
		if (marca_tiempo_msec > actual->time_entry && actual->vecino == 0)
		{
			if(actual == mac_port->inicio)
			{
				mac_port->inicio = actual->next;
				if(mac_port->num_element == 1)
				{
					mac_port->fin = NULL;
					mac_port->inicio = NULL;
				}
				aux = mac_port->inicio;
			}
			else if(actual == mac_port->fin)
			{
				aux->next = NULL;
				mac_port->fin = aux;
			}
			else
				aux->next = actual->next;
			free(actual);
			actual = aux;
			mac_port->num_element--;
		}
		else
			aux = aux -> next;
		actual = aux -> next;
	}
	return 0;
}


int mac_to_port_delete_port(struct mac_to_port *mac_port, int port)
{
	struct mac_port_time *aux = mac_port->inicio;
	struct mac_port_time *actual = mac_port->inicio;

	while (actual != NULL)
	{
		if (actual->port_in == port && actual->vecino == 0)
		{
			if(actual == mac_port->inicio)
			{
				mac_port->inicio = actual->next;
				if(mac_port->num_element == 1)
				{
					mac_port->fin = NULL;
					mac_port->inicio = NULL;
				}
				aux = mac_port->inicio;
			}
			else if(actual == mac_port->fin)
			{
				aux->next = NULL;
				mac_port->fin = aux;
			}
			else
				aux->next = actual->next;
			free(actual);
			actual = aux;
			mac_port->num_element--;
		}
		aux = actual;
		if(actual != NULL)
			actual = actual -> next;
	}
	return 0;
}

void visualizar_tabla(struct mac_to_port *mac_port, int64_t id_datapath)
{
	char mac_tabla[5000];
	struct mac_port_time *aux = mac_port->inicio;
	int i=0,j=0;

	sprintf(mac_tabla, "\npos|      Mac        |Puerto IN|Time|Vecino\n");
	sprintf(mac_tabla + strlen(mac_tabla),"----------------------------------------------\n");
	while(aux != NULL)
	{
		sprintf(mac_tabla + strlen(mac_tabla)," %d |",i+1);
		//pasamos mac_port->fila[i]->Mac a algo legible
		if(aux->Mac != NULL)
		{
			//pasamos mac a que sea legible
			sprintf(mac_tabla + strlen(mac_tabla), "%x:", aux->Mac[0]);
			for(j=1; j<6;j++)
			{
				if(aux->Mac[j])
					sprintf(mac_tabla + strlen(mac_tabla),"%x",aux->Mac[j]);
				if(j!=5)
					sprintf(mac_tabla + strlen(mac_tabla),":");
			}
			//pasamos puerto para ser legible
			sprintf(mac_tabla + strlen(mac_tabla), "| %d |",aux->port_in);

			//pasamos tiempo para ser legible
			if (aux->time_entry > time_msec())
				sprintf(mac_tabla + strlen(mac_tabla),"%.3f |",((float)(aux->time_entry - time_msec()))/1000);
			else
				sprintf(mac_tabla + strlen(mac_tabla),"Caducada |");
			
			//comprobamos el vecino
			sprintf(mac_tabla + strlen(mac_tabla),"%d\n",aux->vecino);
		}
		i++;
		aux = aux->next;
	}
	sprintf(mac_tabla + strlen(mac_tabla),"\n");
	log_uah(mac_tabla,id_datapath);
}

int select_packet_tcp_path(struct packet * pkt, struct table_tcp * tcp_table, int puerto_mac, int TCP_TIME)
{
	uint8_t op = 1;
	
	memcpy(&op,ofpbuf_at(pkt->buffer,(pkt->buffer->size-sizeof(uint8_t)-ETH_ADDR_LEN-sizeof(uint16_t)-sizeof(uint32_t)-sizeof(uint8_t)),sizeof(uint8_t)),sizeof(uint8_t)); 
	
	desencapsulate_path_request_tcp(pkt, op);
	
	//paquete broadcast que siempre llega con puerto_mac = -1 entonces debemos ver el puerto real
	puerto_mac = table_tcp_found_port_in(tcp_table, pkt->handle_std->proto->eth->eth_src,
			pkt->handle_std->proto->eth->eth_dst, pkt->handle_std->proto->tcp->tcp_src,
			pkt->handle_std->proto->tcp->tcp_dst);

	//si no esta en tabla o lo tenemos por el mismo puerto entonces si lo reenviamos si no nada
	if(puerto_mac == -1 || puerto_mac == pkt->in_port)
	{
		if(puerto_mac == -1)
		{
			table_tcp_add(tcp_table, pkt->handle_std->proto->eth->eth_src, pkt->handle_std->proto->eth->eth_dst,pkt->handle_std->proto->tcp->tcp_src, pkt->handle_std->proto->tcp->tcp_dst, pkt->in_port, TCP_TIME);
		}
		//sino lo tratamos como un caso normal y no hace falta crear ni actualizar puesto que se hara despues
	}
	else
	{
		packet_destroy(pkt); //destruimos el paquete si no lo vamos a reenviar
		return -1; //destruimos el paquete
	}
	return 1; 
}

void encapsulate_path_request_tcp(struct packet *pkt)
{
	uint16_t aux_16 = 0;
	uint32_t aux_32 = 0;
    uint8_t broad_mac[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	
	if(pkt->buffer->size < 93 && pkt->handle_std->proto->path == NULL && pkt->handle_std->proto->tcp != NULL)
	{
		if (TCP_FLAGS(pkt->handle_std->proto->tcp->tcp_ctl) == TCP_SYN)
		{
			//incrustamos la nueva parte de la cabecera
			pkt->handle_std->proto->path = xmalloc(sizeof(struct path_header));
			memcpy(pkt->handle_std->proto->path->mac_dst, pkt->handle_std->proto->eth->eth_dst, ETH_ADDR_LEN);
			pkt->handle_std->proto->path->tcp_src = pkt->handle_std->proto->tcp->tcp_src;
			pkt->handle_std->proto->path->tcp_dst = pkt->handle_std->proto->tcp->tcp_dst;
			pkt->handle_std->proto->path->tcp_seq = pkt->handle_std->proto->tcp->tcp_seq;
			pkt->handle_std->proto->path->tcp_ack = pkt->handle_std->proto->tcp->tcp_ack;
			pkt->handle_std->proto->path->tcp_ctl = pkt->handle_std->proto->tcp->tcp_ctl;
			pkt->handle_std->proto->path->tcp_winsz = pkt->handle_std->proto->tcp->tcp_winsz;
			pkt->handle_std->proto->path->tcp_csum = pkt->handle_std->proto->tcp->tcp_csum;
			pkt->handle_std->proto->path->tcp_urg = pkt->handle_std->proto->tcp->tcp_urg;
			//para tracear posibles bucles de los path
			aux_16 = (pkt->dp->id>>8) | (pkt->dp->id<<8);
			pkt->handle_std->proto->path->id_dp = aux_16;
			//ca
			aux_32 =((secuence_path_generic>>24)&0xff) | ((secuence_path_generic<<8)&0xff0000) | 
                    ((secuence_path_generic>>8)&0xff00) | ((secuence_path_generic<<24)&0xff000000); 
			pkt->handle_std->proto->path->secuence = aux_32;
			secuence_path_generic++;
			pkt->handle_std->proto->path->contador = 1;
		
			if(TCP_FLAGS(pkt->handle_std->proto->tcp->tcp_ctl) == TCP_SYN)//SYN
			{
					pkt->handle_std->proto->path->op = 0x01; //Path Request
					//asignamos una mac broadcast para enviarlo por toda la red
					memcpy(pkt->handle_std->proto->eth->eth_dst,broad_mac,ETH_ADDR_LEN);
			}

			pkt->handle_std->proto->ipv4->ip_proto = IP_TYPE_PATH; //IP_TYPE_PATH = 253 codigo exp
			pkt->handle_std->proto->tcp = NULL;

			
			//anyadimos los valores al buffer para que este los cargue en el paquete
			ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->path->op), sizeof(uint8_t));
			ofpbuf_put(pkt->buffer,pkt->handle_std->proto->path->mac_dst, ETH_ADDR_LEN);
			
			//anyadimos los identificadores de traqueo
			ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->path->id_dp), sizeof(uint16_t));
			ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->path->secuence), sizeof(uint32_t));
			ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->path->contador), sizeof(uint8_t));
			
			//validamos nueva cabecera
			pkt->handle_std->valid=false;
			packet_handle_std_validate(pkt->handle_std);
		}
	}
}

void desencapsulate_path_request_tcp(struct packet *pkt, int op)
{
	uint32_t nyapa = 0x00000000;
	uint8_t saltos = 0;

	struct tcp_header * tcp;
	struct ofpbuf *b = ofpbuf_new(pkt->buffer->size-sizeof(uint8_t)-ETH_ADDR_LEN-sizeof(uint16_t)-sizeof(uint32_t)-sizeof(uint8_t)); //nuevo buffer

	//incrustamos la nueva parte de la cabecera
	tcp = xmalloc(sizeof(struct tcp_header));
	tcp->tcp_src  = pkt->handle_std->proto->path->tcp_src;
	tcp->tcp_dst = pkt->handle_std->proto->path->tcp_dst;
	tcp->tcp_seq = pkt->handle_std->proto->path->tcp_seq;
	tcp->tcp_ack = pkt->handle_std->proto->path->tcp_ack;
	tcp->tcp_ctl = pkt->handle_std->proto->path->tcp_ctl;
	tcp->tcp_winsz = pkt->handle_std->proto->path->tcp_winsz;
	tcp->tcp_csum = pkt->handle_std->proto->path->tcp_csum;
	tcp->tcp_urg = pkt->handle_std->proto->path->tcp_urg;
	//quitamos la nueva parte de la cabecera
	if(op == 1)
	{
		//Trackeamos todos los switches por donde ha pasado
		saltos = obtener_saltos(pkt);
		//Mac_dst
		memcpy(pkt->handle_std->proto->eth->eth_dst, 
		ofpbuf_at(pkt->buffer,(pkt->buffer->size-ETH_ADDR_LEN-sizeof(uint16_t)-sizeof(uint32_t)- sizeof(uint8_t)), ETH_ADDR_LEN),ETH_ADDR_LEN);
	}
	
	pkt->handle_std->proto->ipv4->ip_proto = IP_TYPE_TCP;
	pkt->handle_std->proto->tcp = tcp;
	pkt->handle_std->proto->path = NULL;
		
	//nuevo buffer mas pequeño
	ofpbuf_put(b, pkt->buffer->data, pkt->buffer->size - sizeof(uint8_t) - ETH_ADDR_LEN - sizeof(uint16_t) - sizeof(uint32_t) - sizeof(uint8_t));
	pkt-> buffer = b;
	
	//validamos nueva cabecera
	pkt->handle_std->valid=false;
	packet_handle_std_validate(pkt->handle_std);
	
	//sacamos log
	log_tracker_switch_tcp_path(pkt, saltos);
	
	//superchapuza
	if (pkt->buffer->size == 86)
		memcpy((char *)pkt->buffer->data + (pkt->buffer->size - 10*sizeof(uint8_t)), &(nyapa), sizeof(uint32_t));
	else if (pkt->buffer->size == 74)
		memcpy((char *)pkt->buffer->data + (pkt->buffer->size - 8*sizeof(uint8_t)), &(nyapa), sizeof(uint32_t));
}

int is_neighbor(struct packet * pkt)
{
	struct mac_port_time *aux = neighbor_table.inicio; //puntero para recorrer la tabla neighbor_table

	while(aux != NULL)
	{
		if(aux->port_in == pkt->in_port)
			return 0; //no lo es
		aux = aux->next;
	}
	return 1; //es vecino
}

int src_is_neighbor(struct packet *pkt, struct mac_to_port *mac_port)
{
	struct mac_port_time *aux = mac_port->inicio; 
	
	while(aux != NULL)
	{
		if(memcmp( aux->Mac, pkt->handle_std->proto->eth->eth_src, ETH_ADDR_LEN) == 0)
			return aux->vecino; //me indica ya si es vecino o no
		aux = aux->next;
	}
	
	return 0; //es vecino
}

int dst_is_neighbor(struct packet *pkt, struct mac_to_port *mac_port)
{
	struct mac_port_time *aux = mac_port->inicio; 
	uint8_t Mac_dst[ETH_ADDR_LEN]; //mac origen paquete path

	if(pkt->handle_std->proto->path != NULL) //si es un path request de tcp path
	{
		memcpy(Mac_dst, ofpbuf_at(pkt->buffer, (pkt->buffer->size - ETH_ADDR_LEN - sizeof(uint16_t) - sizeof(uint32_t)- sizeof(uint8_t)), ETH_ADDR_LEN), ETH_ADDR_LEN); //obtenemos Mac_dst
	}
	else if(pkt->handle_std->proto->arppath_repair != NULL) // si es un path request de la recuperacion arppath
	{
		memcpy(Mac_dst, ofpbuf_at(pkt->buffer, (pkt->buffer->size - ETH_ADDR_LEN - 32*sizeof(uint8_t)), ETH_ADDR_LEN), ETH_ADDR_LEN); 
	}
	else
		memcpy(Mac_dst, pkt->handle_std->proto->eth->eth_dst, ETH_ADDR_LEN);
	
	while(aux != NULL)
	{
		if(memcmp( aux->Mac, Mac_dst, ETH_ADDR_LEN) == 0)
			return aux->vecino; //me indica ya si es vecino o no
		aux = aux->next;
	}

	return 0; //es vecino

}


int port_is_in_table(struct mac_to_port * table, int port)
{
	struct mac_port_time *aux = table->inicio; //puntero para recorrer la tabla neighbor_table
	while(aux != NULL)
	{
		if(aux->port_in == port)
			return 1; //si esta
		aux = aux->next;
	}
	return 0; //no esta
}


void table_tcp_new(struct table_tcp *tcp_table)
{
        tcp_table->inicio = NULL;
        tcp_table->fin = NULL;
        tcp_table->num_element = 0;
}
//add element to mac to port table
int table_tcp_add(struct table_tcp *tcp_table, uint8_t Mac_src[ETH_ADDR_LEN], uint8_t Mac_dst[ETH_ADDR_LEN], uint16_t port_src,
        uint16_t port_dst, uint16_t port_in, int TCP_TIME)
{
        struct table_tcp_time *nuevo_elemento = NULL;

        if ((nuevo_elemento = xmalloc (sizeof (struct table_tcp_time))) == NULL)
            return -1;

        nuevo_elemento->port_in = port_in;
        nuevo_elemento->time_entry = time_msec() + TCP_TIME*1000;
        memcpy(nuevo_elemento->Mac_src, Mac_src, ETH_ADDR_LEN);
        memcpy(nuevo_elemento->Mac_dst, Mac_dst, ETH_ADDR_LEN);
        nuevo_elemento->port_src = port_src;
        nuevo_elemento->port_dst = port_dst;
        nuevo_elemento->port_out = 0; //no existe camino de vuelta
        //nuevo_elemento->next = tcp_table->inicio; //lo inserto al comienzo

        if (tcp_table->inicio == NULL) //si la lista esta vacia
		{
			nuevo_elemento->next = NULL; //el siguiente puntero no existe = NULL
			tcp_table->fin = nuevo_elemento->next; //como la lista esta vacia la igualo al nuevo
		}
		else //si la lista no esta vacia
			nuevo_elemento->next = tcp_table->inicio; //el siguiente puntero es el que estaba primero
		
		tcp_table->inicio = nuevo_elemento; //el nuevo es el primer elemento
        tcp_table->num_element++;
        return 0;
}

int table_tcp_update_time(struct table_tcp *tcp_table, uint8_t Mac_src[ETH_ADDR_LEN], uint8_t Mac_dst[ETH_ADDR_LEN],
        uint16_t port_src, uint16_t port_dst, int TCP_TIME)
{
    struct table_tcp_time *aux = tcp_table->inicio;
	struct cmp_table_tcp *directo= NULL, *inverso;
		
	//generamos las estructuras para comparar	
	if ((directo = xmalloc (sizeof (struct cmp_table_tcp))) == NULL)
		return -1;
	if ((inverso = xmalloc (sizeof (struct cmp_table_tcp))) == NULL)
		return -1;
	//completamos la rama directa
	memcpy(directo->Mac_src, Mac_src, ETH_ADDR_LEN);
	memcpy(directo->Mac_dst, Mac_dst, ETH_ADDR_LEN);
	directo->port_src = port_src;
	directo->port_dst = port_dst;
	
	//completamos la rama inversa
	memcpy(inverso->Mac_src, Mac_dst, ETH_ADDR_LEN);
	memcpy(inverso->Mac_dst, Mac_src, ETH_ADDR_LEN);
	inverso->port_src = port_dst;
	inverso->port_dst = port_src;
	if (tcp_table->num_element != 0) // si no tenemos elementos mirar es una tonteria
	{
        while(aux != NULL)
        {
			if(memcmp(aux, directo, (2*ETH_ADDR_LEN+4)) == 0)
			{
				aux->time_entry = time_msec()+ TCP_TIME*1000;
				free(inverso);
				free(directo);
				return 0; //todo correcto
			}
			else if(memcmp(aux, inverso, (2*ETH_ADDR_LEN+4)) == 0)
			{
				aux->time_entry = time_msec()+ TCP_TIME*1000;
				free(inverso);
				free(directo);
				return 0; //todo correcto
			}
			aux = aux->next; //pasamos al siguiente elemento de la lista
        }
	}
	free(inverso);
	free(directo);
    return 1;//no se encontro la mac
}

int table_tcp_update_port(struct table_tcp *tcp_table, uint8_t Mac_src[ETH_ADDR_LEN], uint8_t Mac_dst[ETH_ADDR_LEN],
        uint16_t port_src, uint16_t port_dst, int in_port, int TCP_TIME)
{
	struct table_tcp_time *aux = tcp_table->inicio;
	struct cmp_table_tcp *inverso= NULL;
		
	//generamos las estructuras para comparar	
	if ((inverso = xmalloc (sizeof (struct cmp_table_tcp))) == NULL)
		return -1;
	//completamos la rama directa
	memcpy(inverso->Mac_src, Mac_dst, ETH_ADDR_LEN);
	memcpy(inverso->Mac_dst, Mac_src, ETH_ADDR_LEN);
	inverso->port_src = port_dst;
	inverso->port_dst = port_src;
	
	if (tcp_table->num_element != 0) // si no tenemos elementos mirar es una tonteria
	{
		while(aux != NULL)
		{
			if(memcmp(aux, inverso, (2*ETH_ADDR_LEN+4)) == 0)
			{
				aux->port_out = in_port;
				aux->time_entry = time_msec() + TCP_TIME * 1000;
				free(inverso);
				return aux->port_in; //todo correcto
			}
			aux = aux->next; //pasamos al siguiente elemento de la lista
		}
	}
	free(inverso);
	return 0;//no se encontro la mac
}
//found if is posible the out port of the mac
int table_tcp_found_port(struct table_tcp *tcp_table, uint8_t Mac_src[ETH_ADDR_LEN], uint8_t Mac_dst[ETH_ADDR_LEN], 
	uint16_t port_src, uint16_t port_dst)
{
	struct table_tcp_time *aux = tcp_table->inicio;
	struct table_tcp_time *ant = NULL;
	struct cmp_table_tcp *directo= NULL, *inverso = NULL;
	int pos = 0, port_select = -1;
		
	//generamos las estructuras para comparar	
	if ((directo = xmalloc (sizeof (struct cmp_table_tcp))) == NULL)
		return -1;
	if ((inverso = xmalloc (sizeof (struct cmp_table_tcp))) == NULL)
		return -1;
	//completamos la rama directa
	memcpy(directo->Mac_src, Mac_src, ETH_ADDR_LEN);
	memcpy(directo->Mac_dst, Mac_dst, ETH_ADDR_LEN);
	directo->port_src = port_src;
	directo->port_dst = port_dst;
	
	//completamos la rama inversa
	memcpy(inverso->Mac_src, Mac_dst, ETH_ADDR_LEN);
	memcpy(inverso->Mac_dst, Mac_src, ETH_ADDR_LEN);
	inverso->port_src = port_dst;
	inverso->port_dst = port_src;
	
	
	if (tcp_table->num_element != 0) // si no tenemos elementos mirar es una tonteria
	{
        while(aux != NULL || port_select != -1)
        {
			pos ++; //contamos el numero de avanze
			if(memcmp(aux, directo, (2*ETH_ADDR_LEN+4)) == 0)
			{
				port_select = aux->port_out; //todo sacamos el puerto direccion al destino
				break;
			}
			else if(memcmp(aux, inverso, (2*ETH_ADDR_LEN+4)) == 0)
			{
				port_select =  aux->port_in; //tsacamos el puerto dirección al destino
				break;
			}
			else
			{
				ant = aux; //siempre necesitamos uno por detras para hacer los empalmes
				aux = aux->next; //pasamos el aux al siguiente 
			}
        }
		//si estamos lejos del comienzo de busqueda lo subimos // 
		if (pos > 2 && port_select > 0)
		{
			//1º como tenemos seleccionado el que vamos a mover, rearmamos la fila
			ant->next = aux->next;
			if(ant->next == NULL) // si no existe elemento siguiente, entonces somos el ultimo
				tcp_table->fin = ant; //modificamos el ultimo elemento
			aux->next = tcp_table->inicio; //enlazamos el antiguo 1º al nuevo 
			tcp_table->inicio = aux; //colocamos el elemento encontrado como primero
		}
	}
	free(inverso);
	free(directo);
	return port_select;
		
}
int table_tcp_found_port_in(struct table_tcp *tcp_table, uint8_t Mac_src[ETH_ADDR_LEN], uint8_t Mac_dst[ETH_ADDR_LEN],
        uint16_t port_src, uint16_t port_dst)
{
	struct table_tcp_time *aux = tcp_table->inicio;
	int pos = 0, port_select = -1;
	struct cmp_table_tcp *directo= NULL;
	
		
	//generamos las estructuras para comparar	
	if ((directo = xmalloc (sizeof (struct cmp_table_tcp))) == NULL)
		return -1;
	//completamos la rama directa
	memcpy(directo->Mac_src, Mac_src, ETH_ADDR_LEN);
	memcpy(directo->Mac_dst, Mac_dst, ETH_ADDR_LEN);
	directo->port_src = port_src;
	directo->port_dst = port_dst;
		
	if (tcp_table->num_element != 0) // si no tenemos elementos mirar es una tonteria
	{
        while(aux != NULL || port_select != -1)
        {
			pos ++; //contamos el numero de avanze
			if(memcmp(aux, directo, (2*ETH_ADDR_LEN+4)) == 0)
			{
				port_select = aux->port_in; //todo sacamos el puerto direccion al destino
				free(directo);
				return port_select;
			}
			else
				aux = aux->next; //pasamos el aux al siguiente 
        }
	}
	free(directo);
	return -1;
}
int table_tcp_check_timeout(struct table_tcp *tcp_table, uint8_t Mac_src[ETH_ADDR_LEN], uint8_t Mac_dst[ETH_ADDR_LEN],
        uint16_t port_src, uint16_t port_dst)
{
	struct table_tcp_time *aux = tcp_table->inicio;
	struct cmp_table_tcp *directo= NULL, *inverso =NULL;
	uint64_t marca_tiempo_msec = time_msec();
	int respuesta = -1;
	
	//generamos las estructuras para comparar	
	if ((directo = xmalloc (sizeof (struct cmp_table_tcp))) == NULL)
		return respuesta;
	//completamos la rama directa
	memcpy(directo->Mac_src, Mac_src, ETH_ADDR_LEN);
	memcpy(directo->Mac_dst, Mac_dst, ETH_ADDR_LEN);
	directo->port_src = port_src;
	directo->port_dst = port_dst;
	
	//generamos las estructuras para comparar	
	if ((inverso = xmalloc (sizeof (struct cmp_table_tcp))) == NULL)
		return respuesta;
	//completamos la rama directa
	memcpy(inverso->Mac_src, Mac_dst, ETH_ADDR_LEN);
	memcpy(inverso->Mac_dst, Mac_src, ETH_ADDR_LEN);
	inverso->port_src = port_dst;
	inverso->port_dst = port_src;
	
	if (tcp_table->num_element != 0) // si no tenemos elementos mirar es una tonteria
	{
        while(aux != NULL)
        {
			if(memcmp(aux, directo, (2*ETH_ADDR_LEN+4)) == 0 || memcmp(aux, inverso, (2*ETH_ADDR_LEN+4)) == 0)
			{
				if(marca_tiempo_msec > aux->time_entry)
					respuesta = 1; //el time out ha saltado
				else
					respuesta = 0; //el time no ha saltado
				break;
			}
			aux = aux->next;
        }
	}	
	free (directo);
	free (inverso);
	return respuesta; //si no existe tal puerto

}
//check de timeout of the mac and port
int table_tcp_delete_timeout(struct table_tcp *tcp_table)
{
	struct table_tcp_time *aux = tcp_table->inicio;
	struct table_tcp_time *actual = tcp_table->inicio;
	uint64_t marca_tiempo_msec = time_msec();
	
	while (actual != NULL)
	{
		if (tcp_table->num_element > 2)
		{		
			if (marca_tiempo_msec >= actual->time_entry)
			{
				if(actual == tcp_table->inicio)
				{
					if(tcp_table->num_element != 1)
						tcp_table->inicio = actual->next;
					else
					{
						tcp_table->fin = NULL;
						tcp_table->inicio = NULL;
					}
					aux = tcp_table->inicio;
				}
				else if(actual == tcp_table->fin)
				{
					aux->next = NULL;
					tcp_table->fin = aux;
				}
				else
					aux->next = actual->next; //siguiente al anterior es el siguiente al actual
				free(actual);
				actual = aux;
				tcp_table->num_element--;
			}
			aux = actual;
			actual = aux -> next;
		}
		else
			actual = NULL;
	}
	return 0;
}

//chect port and delete of table
int tcp_delete_port(struct table_tcp *tcp_table, uint8_t Mac_src[ETH_ADDR_LEN], uint8_t Mac_dst[ETH_ADDR_LEN],
        uint16_t port_src, uint16_t port_dst)
{
	struct table_tcp_time *aux = tcp_table->inicio;
	struct table_tcp_time *actual = tcp_table->inicio;
	struct cmp_table_tcp *directo= NULL;
	
	//generamos las estructuras para comparar	
	if ((directo = xmalloc (sizeof (struct cmp_table_tcp))) == NULL)
		return -1;
	//completamos la rama directa
	memcpy(directo->Mac_src, Mac_src, ETH_ADDR_LEN);
	memcpy(directo->Mac_dst, Mac_dst, ETH_ADDR_LEN);
	directo->port_src = port_src;
	directo->port_dst = port_dst;
	
	while (actual != NULL)
	{
		if (memcmp(aux, directo, (2*ETH_ADDR_LEN+4)) == 0)
		{
			if(actual == tcp_table->inicio)
			{
				tcp_table->inicio = actual->next;
				aux = tcp_table->inicio;
				if(tcp_table->num_element == 1)
				{
					tcp_table->fin = NULL;
					tcp_table->inicio = NULL;
				}
			}
			else if(actual == tcp_table->fin)
			{
				aux->next = NULL;
				tcp_table->fin = aux;
			}
			else
				aux->next = actual->next;
			free(actual);
			actual = aux;
			tcp_table->num_element--;
			free(directo);
			return 1;
		}
		aux = actual;
		if(actual != NULL)
			actual = actual -> next;
	}
	free(directo);
	return 0;
}
void visualizar_mac(uint8_t mac[ETH_ADDR_LEN], int64_t id)
{
	char mac_tabla[20];
	int j=0;
	
	//pasamos mac a que sea legible
	sprintf(mac_tabla, "%x:", mac[0]);
	for(j=1; j<6;j++)
	{
		if(mac[j])
			sprintf(mac_tabla + strlen(mac_tabla),"%x",mac[j]);
		if(j!=5)
			sprintf(mac_tabla + strlen(mac_tabla),":");
	}
	sprintf(mac_tabla + strlen(mac_tabla),"\n");
	log_uah(mac_tabla,id);
}

void visualizar_tabla_tcp(struct table_tcp *tcp, int64_t id_datapath)
{
	char mac_tabla[400];
	struct table_tcp_time *aux = tcp->inicio;
	int i=1, j = 0;

	log_uah("\npos|      Mac src    |Puerto Src|    Mac Dst     |Puerto Dst|Puerto IN|Puerto Out|Time\n",id_datapath);
	log_uah("---------------------------------------------------------------------------------------------\n",id_datapath);
	while(aux != NULL)
	{
		sprintf(mac_tabla,"%d|",i);
		//pasamos mac a que sea legible
		sprintf(mac_tabla + strlen(mac_tabla), "%x:", aux->Mac_src[0]);
		for(j=1; j<6;j++)
		{
			if(aux->Mac_src[j])
				sprintf(mac_tabla + strlen(mac_tabla),"%x",aux->Mac_src[j]);
			if(j!=5)
				sprintf(mac_tabla + strlen(mac_tabla),":");
		}
		sprintf(mac_tabla + strlen(mac_tabla), "|%d|",aux->port_src);
		//pasamos mac a que sea legible
		sprintf(mac_tabla + strlen(mac_tabla), "%x:", aux->Mac_dst[0]);
		for(j=1; j<6;j++)
		{
			if(aux->Mac_dst[j])
				sprintf(mac_tabla + strlen(mac_tabla),"%x",aux->Mac_dst[j]);
			if(j!=5)
				sprintf(mac_tabla + strlen(mac_tabla),":");
		}
		//siguiente seccion
		sprintf(mac_tabla + strlen(mac_tabla), "|%d|",aux->port_dst);
		//pasamos puerto para ser legible
		sprintf(mac_tabla + strlen(mac_tabla), "%d|",aux->port_in);
		//pasamos puerto para ser legible
		sprintf(mac_tabla + strlen(mac_tabla), "%d|",aux->port_out);
		//pasamos tiempo para ser legible
		if (time_msec() < aux->time_entry)
			sprintf(mac_tabla + strlen(mac_tabla),"%4f\n",((float)(aux->time_entry - time_msec())/1000));
		else
			sprintf(mac_tabla + strlen(mac_tabla),"Caducada\n");
		log_uah(mac_tabla,id_datapath);

		i++;
		aux = aux->next;
	}
	log_uah("\n",id_datapath);
}
void keep_arp_path(struct packet * pkt, struct mac_to_port *mac_port)
{
	int i = 0; //contador
	struct packet *arp_pkt = NULL, *pkt_aux;

	if(dst_is_neighbor(pkt, mac_port) == 1) //el destino es vecino del switch
	{
		log_arp_path(pkt, pkt->dp->id);//si es vecino apuntamos el log puesto lo vamos a sacar por el puerto destino
		if(pkt->handle_std->proto->arppath != NULL) //si NO es arp lo desencapsulamos
			desencapsulate_arp_path(pkt);
	}
	else //no es vecino del switch
	{
		//Primer caso, venga un arp normal, debemos encapsular
		if(pkt->handle_std->proto->eth->eth_type == 1544)
				encapsulate_arp_path(pkt);
		else if(pkt->handle_std->proto->arppath != NULL) //si viene encapsulado
				keep_id_switch(pkt, pkt->dp->id);
		//si paquete broadcast debemos reenviar el clonado a los host vecinos
		if (eth_addr_is_broadcast(pkt->handle_std->proto->eth->eth_dst)
				|| eth_addr_is_multicast(pkt->handle_std->proto->eth->eth_dst))
		{
			arp_pkt = packet_clone(pkt);
			if(arp_pkt->handle_std->proto->arppath == NULL) //si NO es arp lo desencapsulamos
					return; //por si se escapa algun paquete no deseado
			for(i = 1; i < arp_pkt->dp->ports_num; i++) //miramos todos los puerto activos
			{
				if (port_is_in_table(&neighbor_table, i) == 0
					&& arp_pkt->dp->ports[i].conf->state == OFPPS_LIVE) //no esta en la tabla de vecinos
				{
					pkt_aux = packet_clone(arp_pkt);
					log_arp_path(arp_pkt, arp_pkt->dp->id);
					desencapsulate_arp_path(arp_pkt);
					//dp_actions_output_port(arp_pkt, i, arp_pkt->out_queue, arp_pkt->out_port_max_len,							0xffffffffffffffff);
					//recuperamos el paquete original
					arp_pkt = packet_clone(pkt_aux);
					//destruimos el copia
					packet_destroy(pkt_aux);
				}
			}
			//destruimos el de reenvio
			packet_destroy(arp_pkt);
		}
	}
}
//encapsulate arp -> arppath
void encapsulate_arp_path(struct packet *pkt)
{
	//incrustamos la nueva parte de la cabecera
	pkt->handle_std->proto->arppath = xmalloc(sizeof(struct arp_path_header));
	pkt->handle_std->proto->arppath->ar_hrd = pkt->handle_std->proto->arp->ar_hrd;
	pkt->handle_std->proto->arppath->ar_pro = pkt->handle_std->proto->arp->ar_pro;
	pkt->handle_std->proto->arppath->ar_hln = pkt->handle_std->proto->arp->ar_hln;
	pkt->handle_std->proto->arppath->ar_pln = pkt->handle_std->proto->arp->ar_pln;
	pkt->handle_std->proto->arppath->ar_op = pkt->handle_std->proto->arp->ar_op;
	memcpy(pkt->handle_std->proto->arppath->ar_sha,pkt->handle_std->proto->arp->ar_sha,ETH_ADDR_LEN);
	pkt->handle_std->proto->arppath->ar_spa = pkt->handle_std->proto->arp->ar_spa;
	memcpy(pkt->handle_std->proto->arppath->ar_tha,pkt->handle_std->proto->arp->ar_tha,ETH_ADDR_LEN);
	pkt->handle_std->proto->arppath->ar_tpa = pkt->handle_std->proto->arp->ar_tpa;

	pkt->handle_std->proto->eth->eth_type = ETH_TYPE_ARPPATH_UAH;
	pkt->handle_std->proto->arp = NULL;
	pkt->handle_std->valid = false;

	keep_id_switch(pkt, pkt->dp->id); //insertamos el valor id del sw 1
}
void desencapsulate_arp_path(struct packet *pkt)
{
	//incrustamos la nueva parte de la cabecera
	pkt->handle_std->proto->arp = xmalloc(sizeof(struct arp_eth_header));
	pkt->handle_std->proto->arp->ar_hrd = pkt->handle_std->proto->arppath->ar_hrd;
	pkt->handle_std->proto->arp->ar_pro = pkt->handle_std->proto->arppath->ar_pro;
	pkt->handle_std->proto->arp->ar_hln = pkt->handle_std->proto->arppath->ar_hln;
	pkt->handle_std->proto->arp->ar_pln = pkt->handle_std->proto->arppath->ar_pln;
	pkt->handle_std->proto->arp->ar_op = pkt->handle_std->proto->arppath->ar_op;
	memcpy(pkt->handle_std->proto->arp->ar_sha,pkt->handle_std->proto->arppath->ar_sha,ETH_ADDR_LEN);
	pkt->handle_std->proto->arp->ar_spa = pkt->handle_std->proto->arppath->ar_spa;
	memcpy(pkt->handle_std->proto->arp->ar_tha,pkt->handle_std->proto->arppath->ar_tha,ETH_ADDR_LEN);
	pkt->handle_std->proto->arp->ar_tpa = pkt->handle_std->proto->arppath->ar_tpa;


	pkt->handle_std->proto->eth->eth_type = 0x0608;

	pkt->handle_std->valid=false;
	pkt->handle_std->proto->arppath = NULL;

	pkt->buffer->size = 42;

	//validamos nueva cabecera
	packet_handle_std_validate(pkt->handle_std);

}

//keep switch id in pkt
void keep_id_switch(struct packet *pkt, int id)
{
	if (pkt->buffer->size < 64) //si es el primero anyadimos todo de golpe
	{
		pkt->handle_std->proto->arppath->arpt_sw1 = id;
		ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->arppath->arpt_sw1), sizeof(uint32_t));
	}
	else if (pkt->buffer->size == 64)
	{
		pkt->handle_std->proto->arppath->arpt_sw2 = id;
		ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->arppath->arpt_sw2), sizeof(uint32_t));
	}
	else if (pkt->buffer->size == 68)
	{
		pkt->handle_std->proto->arppath->arpt_sw3 = id;
		ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->arppath->arpt_sw3), sizeof(uint32_t));
	}
	else if (pkt->buffer->size == 72)
	{
		pkt->handle_std->proto->arppath->arpt_sw4 = id;
		ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->arppath->arpt_sw4), sizeof(uint32_t));
	}
	else if (pkt->buffer->size == 76)
	{
		pkt->handle_std->proto->arppath->arpt_sw5 = id;
		ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->arppath->arpt_sw5), sizeof(uint32_t));
	}
	else if (pkt->buffer->size == 80)
	{
		pkt->handle_std->proto->arppath->arpt_sw6 = id;
		ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->arppath->arpt_sw6), sizeof(uint32_t));
	}
	else if (pkt->buffer->size == 84)
	{
		pkt->handle_std->proto->arppath->arpt_sw7 = id;
		ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->arppath->arpt_sw7), sizeof(uint32_t));
	}
	else if (pkt->buffer->size == 88)
	{
		pkt->handle_std->proto->arppath->arpt_sw8 = id;
		ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->arppath->arpt_sw8), sizeof(uint32_t));
	}
	else if (pkt->buffer->size == 92)
	{
		pkt->handle_std->proto->arppath->arpt_sw9 = id;
		ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->arppath->arpt_sw9), sizeof(uint32_t));
	}
	else if (pkt->buffer->size == 96)
	{
		pkt->handle_std->proto->arppath->arpt_sw10 = id;
		ofpbuf_put(pkt->buffer,&(pkt->handle_std->proto->arppath->arpt_sw10), sizeof(uint32_t));
	}
	pkt->handle_std->valid=false;
	packet_handle_std_validate(pkt->handle_std);
}

//keep switch id in pkt
void switch_track_tcp(struct packet *pkt)
{
	memcpy(&(pkt->handle_std->proto->path->contador), 
		ofpbuf_at(pkt->buffer, (pkt->buffer->size - sizeof(uint8_t)), sizeof(uint8_t)), 
		sizeof(uint8_t));
		
	pkt->handle_std->proto->path->contador++;
	//Inserta el valor deseado en la posicion del paquete
	memcpy((char *)pkt->buffer->data + (pkt->buffer->size - sizeof(uint8_t)), &(pkt->handle_std->proto->path->contador), sizeof(uint8_t));
				
	pkt->handle_std->valid=false;
	packet_handle_std_validate(pkt->handle_std);
}

uint8_t obtener_saltos(struct packet *pkt)
{
	uint8_t saltos;
	memcpy(&(saltos), ofpbuf_at(pkt->buffer, (pkt->buffer->size - sizeof(uint8_t)), sizeof(uint8_t)), sizeof(uint8_t));
	return (saltos+1);
}

void log_tracker_switch_tcp_path(struct packet *pkt, uint8_t saltos)
{
	FILE * file;
	char texto[100], nombre[50];
	
	sprintf(nombre,"/home/arppath/TAOSSv2/logs/log_track_path_%d.log",(int)pkt->dp->id);
	file = fopen( nombre , "a" );
	if(pkt->handle_std->proto->tcp != NULL) //si el paquete esta encapsulado
	{
		sprintf(texto,"%u\t",saltos);
		sprintf(texto + strlen(texto),"%d\t", (int)pkt->dp->id);
		sprintf(texto + strlen(texto),"%d\t", (int)pkt->in_port);
		sprintf(texto + strlen(texto),"%d\t", (int)pkt->buffer->size);
		sprintf(texto + strlen(texto),"%u\t",pkt->handle_std->proto->tcp->tcp_src);
		sprintf(texto + strlen(texto),"%u\t",pkt->handle_std->proto->tcp->tcp_dst);
		sprintf(texto + strlen(texto),"%lu\t", (long)time_msec());
		
		sprintf(texto + strlen(texto),"\n");
		fputs(texto, file);
	}
	fclose(file);
}

//log arp path camino
void log_arp_path(struct packet *pkt, int id_final)
{
	FILE * file;
	char texto[400];

	if(pkt->handle_std->proto->arppath != NULL) //si el paquete esta encapsulado
	{
		if (!(eth_addr_is_broadcast(pkt->handle_std->proto->eth->eth_dst)
				|| eth_addr_is_multicast(pkt->handle_std->proto->eth->eth_dst)))
				sprintf(texto,"u|");
		else
				sprintf(texto,"B|");

		if( pkt->handle_std->proto->arppath->ar_op/256 == 1)
				sprintf(texto + strlen(texto),"Arp Request|");
		else
				sprintf(texto + strlen(texto),"Arp Reply  |");
		sprintf(texto + strlen(texto),IP_FMT, IP_ARGS(&pkt->handle_std->proto->arppath->ar_spa));
		sprintf(texto + strlen(texto),"|");
		sprintf(texto + strlen(texto),IP_FMT, IP_ARGS(&pkt->handle_std->proto->arppath->ar_tpa));
		sprintf(texto + strlen(texto),"|");
	if (pkt->handle_std->proto->arppath->arpt_sw5/65536 != 0 && pkt->buffer->size > 60)
				sprintf(texto + strlen(texto),"%x|", pkt->handle_std->proto->arppath->arpt_sw5/65536);
		if (pkt->handle_std->proto->arppath->arpt_sw6/65536 != 0 && pkt->buffer->size > 64)
				sprintf(texto + strlen(texto),"%x|", pkt->handle_std->proto->arppath->arpt_sw6/65536);
		if (pkt->handle_std->proto->arppath->arpt_sw7/65536 != 0 && pkt->buffer->size > 68)
				sprintf(texto + strlen(texto),"%x|", pkt->handle_std->proto->arppath->arpt_sw7/65536);
		if (pkt->handle_std->proto->arppath->arpt_sw8/65536 != 0 && pkt->buffer->size > 72)
				sprintf(texto + strlen(texto),"%x|", pkt->handle_std->proto->arppath->arpt_sw8/65536);
		if (pkt->handle_std->proto->arppath->arpt_sw9/65536 != 0 && pkt->buffer->size > 76)
				sprintf(texto + strlen(texto),"%x|", pkt->handle_std->proto->arppath->arpt_sw9/65536);
		if (pkt->handle_std->proto->arppath->arpt_sw10/65536 != 0 && pkt->buffer->size > 80)
				sprintf(texto + strlen(texto),"%x|", pkt->handle_std->proto->arppath->arpt_sw10/65536);
	}
	else if (pkt->handle_std->proto->arp != NULL) //si el paquete esta desencapsulado
	{
		if( pkt->handle_std->proto->arp->ar_op/256 == 1)
				sprintf(texto,"Arp Request|");
		else
				sprintf(texto,"Arp Reply  |");
		sprintf(texto,IP_FMT, IP_ARGS(&pkt->handle_std->proto->arp->ar_spa));
		sprintf(texto + strlen(texto),"|");
		sprintf(texto + strlen(texto),IP_FMT, IP_ARGS(&pkt->handle_std->proto->arp->ar_tpa));
		sprintf(texto + strlen(texto),"|");
	}

	if (!(eth_addr_is_broadcast(pkt->handle_std->proto->eth->eth_dst)
					|| eth_addr_is_multicast(pkt->handle_std->proto->eth->eth_dst)))
			sprintf(texto + strlen(texto),"%x\n",id_final);
	else
			sprintf(texto + strlen(texto),"\n");

	file = fopen( "/home/arppath/TAOSSv2/logs/arp_path_camino.log" , "a" );
	fputs(texto, file);
	fclose(file);
}

void log_uah(const void *Mensaje, int64_t id)
{

	FILE * file;
	char nombre[90], nombre2[90];

	VLOG_DBG_RL(LOG_MODULE, &rl, "Traza UAH -> Entro a Crear Log");
	sprintf(nombre,"/home/arppath/TAOSSv2/logs/arp_path_module_switch_%d.log",(int)id);
	
	file=fopen(nombre,"a");
	if(file != NULL)
	{
		fseek(file, 0L, SEEK_END);
		if(ftell(file) > 16000)
		{
			fclose(file);
			sprintf(nombre2,"/home/arppath/TAOSSv2/logs/arp_path_module_switch_%d-%lu.log",(int)id,(long)time_msec());
			rename(nombre,nombre2);
		}
		file = fopen( nombre , "a" );
		fputs(Mensaje, file);
		fclose(file);
	}
	else
		VLOG_DBG_RL(LOG_MODULE, &rl, "Traza UAH -> Archivo no abierto");
}

//modificacion para arppath as a service
void modificar_nuevo_switch_arppath_as_a_service(struct packet *pkt, int64_t id)
{
	memcpy((char *)pkt->buffer->data + (pkt->buffer->size - (45*sizeof(uint8_t)+sizeof(id))), &(id), sizeof(int64_t));
				
	pkt->handle_std->valid=false;
	packet_handle_std_validate(pkt->handle_std);
}

void insertar_outport_pkt(struct packet *pkt, int port)
{
	memcpy((char *)pkt->buffer->data + (pkt->buffer->size - (45*sizeof(uint8_t))), &(port), sizeof(int));
	pkt->handle_std->valid=false;
	packet_handle_std_validate(pkt->handle_std);
}

void indicar_posicion_ptk_arppath_as_a_service(struct packet *pkt, int8_t pos)
{
	memcpy((char *)pkt->buffer->data + (pkt->buffer->size - (45*sizeof(uint8_t)-2*sizeof(int))), &(pos), sizeof(uint8_t));
				
	pkt->handle_std->valid=false;
	packet_handle_std_validate(pkt->handle_std);
}



/*FIN UAH*/
