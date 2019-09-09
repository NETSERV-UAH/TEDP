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

#include <config.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "command-line.h"
#include "daemon.h"
#include "datapath.h"
#include "fault.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "queue.h"
#include "util.h"
#include "rconn.h"
#include "timeval.h"
#include "vconn.h"
#include "dirs.h"
#include "vconn-ssl.h"
#include "vlog-socket.h"

#if defined(OF_HW_PLAT)
#include <openflow/of_hw_api.h>
#endif

#define THIS_MODULE VLM_udatapath
#include "vlog.h"

//Modificacion UAH
#include <time.h>
#include <sys/time.h>

#define TIME_SEND 5
#define TIME_ARPPATH_SERVICE 5
#define TIME_ARP 10
#define TIME_DELETE_NEIGHBOR 10 
#define TIME_RECOVERY 2

int udatapath_cmd(int argc, char *argv[]);

static void parse_options(struct datapath *dp, int argc, char *argv[]);
static void usage(void) NO_RETURN;

static struct datapath *dp;

static char *port_list;
static char *local_port = "tap:";

static void add_ports(struct datapath *dp, char *port_list);

static bool use_multiple_connections = false;

//paquete hello previamente creado y del nuevo mensaje arppathasservice
extern struct packet *pkt_hello_propio_aoss, *pkt_arppath_as_service;
//vecinos globales para asi poder pasar y seleccionar envios
extern struct mac_to_port neighbor_table, Arppath_as_a_service_table;
//para bloqueo de paquetes arppath as a service
//para matriz de broadcast
extern int * Matriz_bc[16];
static void matriz_aleatoria_gen(void);
extern uint32_t secuence_path_generic; 



/* Need to treat this more generically */
#if defined(UDATAPATH_AS_LIB)
#define OFP_FATAL(_er, _str, args...) do {                \
        fprintf(stderr, _str, ## args);                   \
        return -1;                                        \
    } while (0)
#else
#define OFP_FATAL(_er, _str, args...) ofp_fatal(_er, _str, ## args)
#endif

#if !defined(UDATAPATH_AS_LIB)
int
main(int argc, char *argv[])
{
    return udatapath_cmd(argc, argv);
	
}
#endif

int
udatapath_cmd(int argc, char *argv[])
{
    int n_listeners;
    int error;
    int i;

    //Modificacion UAH
    uint64_t sendtime = 0, arptime=0, inicio_arppath_service = 0, arpservice_time = 0;//, neighbortime=0; //, recoverytime=0;

	uint8_t puerto_no_disponible = 0;
	struct timeval t_ini_recuperacion; //para la toma de medidas de recuperacion

    struct mac_to_port mac_port;
    struct mac_to_port recovery_table;
	secuence_path_generic = 0;
	
    //Fin modificacion uah
    set_program_name(argv[0]);
    register_fault_handlers();
    time_init();
    vlog_init();

    dp = dp_new();
    //modificacion uah
    mac_to_port_new(&mac_port);
    mac_to_port_new(&neighbor_table);
    mac_to_port_new(&recovery_table);
	mac_to_port_new(&Arppath_as_a_service_table);
    //fin modificacion uah
	
    parse_options(dp, argc, argv);
    signal(SIGPIPE, SIG_IGN);

    if (argc - optind < 1) {
        OFP_FATAL(0, "at least one listener argument is required; "
          "use --help for usage");
    }

    if (use_multiple_connections && (argc - optind) % 2 != 0)
        OFP_FATAL(0, "when using multiple connections, you must specify an even number of listeners");
        
    n_listeners = 0;
    for (i = optind; i < argc; i += 2) {
        const char *pvconn_name = argv[i];
        const char *pvconn_name_aux = NULL;
        struct pvconn *pvconn, *pvconn_aux = NULL;
        int retval, retval_aux;

        if (use_multiple_connections)
            pvconn_name_aux = argv[i + 1];

        retval = pvconn_open(pvconn_name, &pvconn);
        if (!retval || retval == EAGAIN) {
            // Get another listener if we are using auxiliary connections
            if (use_multiple_connections) {
                retval_aux = pvconn_open(pvconn_name_aux, &pvconn_aux);
                if (retval_aux && retval_aux != EAGAIN) {
                    ofp_error(retval_aux, "opening auxiliary %s", pvconn_name_aux);
                    pvconn_aux = NULL;
                }
            }
            dp_add_pvconn(dp, pvconn, pvconn_aux);
            n_listeners++;
        } else {
            ofp_error(retval, "opening %s", pvconn_name);
        }
    }
    if (n_listeners == 0) {
        OFP_FATAL(0, "could not listen for any connections");
    }

    if (port_list != NULL) {
        add_ports(dp, port_list);
    }
    if (local_port != NULL) {
        error = dp_ports_add_local(dp, local_port);
        if (error) {
            OFP_FATAL(error, "failed to add local port %s", local_port);
        }
    }

    error = vlog_server_listen(NULL, NULL);
    if (error) {
        OFP_FATAL(error, "could not listen for vlog connections");
    }

    die_if_already_running();
    daemonize();

	//modificacion uah
	matriz_aleatoria_gen();
	//Estos paquete una vez creados no hace falta volver a crearlos puesto que no cambian
	pkt_hello_propio_aoss = packet_hello_create(dp, 0, 1);
	//paquete arppath as a service
	pkt_arppath_as_service = packet_Arppath_as_a_service_create(dp, 0, 1);
	arpservice_time = time_msec();
	arptime=time_msec();
	//neighbortime=time_msec(); 
	//recoverytime=time_msec();
	//tomamos medida para el inicio random de arppath as a service
	//el random puede llevar como maximo 15 segundos entre el primero y el ultimo
	inicio_arppath_service = time_msec() + ((rand() % 15)*1000);
	
	for (;;) {
		dp_run(dp,&mac_port, &recovery_table, &puerto_no_disponible, &t_ini_recuperacion);
		dp_wait(dp);
		poll_block();
		//delete table entry 
		if(time_msec() - sendtime > TIME_SEND*1000)
		{
			packet_hello_send(); //lanzamos el paquete de hello
			sendtime = time_msec();
		}
		if(time_msec() - arptime > TIME_ARP*1000)
		{
			arptime = time_msec();
			mac_to_port_delete_timeout(&mac_port);
		}
		//solo iniciamos el arppath si somos tores
		if((inicio_arppath_service < time_msec()) && (time_msec() - arpservice_time > TIME_ARPPATH_SERVICE*1000) && (dp->id < 0x100))
		{
			//limpiamos las tablas cada X segundo antes de enviar los nuevos paquetes
			mac_to_port_delete_timeout(&Arppath_as_a_service_table);
			packet_arppath_as_a_service_send(); //lanzamos el paquete de exploracion */
			arpservice_time = time_msec();
		}
    }

    return 0;
}

static void
add_ports(struct datapath *dp, char *port_list)
{
    char *port, *save_ptr;

    /* Glibc 2.7 has a bug in strtok_r when compiling with optimization that
     * can cause segfaults here:
     * http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614.
     * Using ",," instead of the obvious "," works around it. */
    for (port = strtok_r(port_list, ",,", &save_ptr); port;
         port = strtok_r(NULL, ",,", &save_ptr)) {
        int error = dp_ports_add(dp, port);
        if (error) {
            ofp_fatal(error, "failed to add port %s", port);
        }
    }
}

static void
parse_options(struct datapath *dp, int argc, char *argv[])
{
    enum {
        OPT_MFR_DESC = UCHAR_MAX + 1,
        OPT_HW_DESC,
        OPT_SW_DESC,
        OPT_DP_DESC,
        OPT_SERIAL_NUM,
        OPT_BOOTSTRAP_CA_CERT,
        OPT_NO_LOCAL_PORT,
        OPT_NO_SLICING
    };

    static struct option long_options[] = {
        {"interfaces",  required_argument, 0, 'i'},
        {"local-port",  required_argument, 0, 'L'},
        {"no-local-port", no_argument, 0, OPT_NO_LOCAL_PORT},
        {"datapath-id", required_argument, 0, 'd'},
        {"multiconn",     no_argument, 0, 'm'},
        {"verbose",     optional_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        {"no-slicing",  no_argument, 0, OPT_NO_SLICING},
        {"mfr-desc",    required_argument, 0, OPT_MFR_DESC},
        {"hw-desc",     required_argument, 0, OPT_HW_DESC},
        {"sw-desc",     required_argument, 0, OPT_SW_DESC},
        {"dp_desc",  required_argument, 0, OPT_DP_DESC},
        {"serial_num",  required_argument, 0, OPT_SERIAL_NUM},
        DAEMON_LONG_OPTIONS,
#ifdef HAVE_OPENSSL
        VCONN_SSL_LONG_OPTIONS
        {"bootstrap-ca-cert", required_argument, 0, OPT_BOOTSTRAP_CA_CERT},
#endif
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int indexptr;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, &indexptr);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'd': {
            uint64_t dpid;
            if (strlen(optarg) != 12
                || strspn(optarg, "0123456789abcdefABCDEF") != 12) {
                ofp_fatal(0, "argument to -d or --datapath-id must be "
                          "exactly 12 hex digits");
            }
            dpid = strtoll(optarg, NULL, 16);
            if (!dpid) {
                ofp_fatal(0, "argument to -d or --datapath-id must "
                          "be nonzero");
            }
            dp_set_dpid(dp, dpid);
            break;
        }
        
        case 'm': {
            use_multiple_connections = true;
            break;
        }
        
        case 'h':
            usage();

        case 'V':
            printf("%s %s compiled "__DATE__" "__TIME__"\n",
                   program_name, VERSION BUILDNR);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        case 'i':
            if (!port_list) {
                port_list = optarg;
            } else {
                port_list = xasprintf("%s,%s", port_list, optarg);
            }
            break;

        case 'L':
            local_port = optarg;
            break;

        case OPT_NO_LOCAL_PORT:
            local_port = NULL;
            break;

        case OPT_MFR_DESC:
            dp_set_mfr_desc(dp, optarg);
            break;

        case OPT_HW_DESC:
            dp_set_hw_desc(dp, optarg);
            break;

        case OPT_SW_DESC:
            dp_set_sw_desc(dp, optarg);
            break;

        case OPT_DP_DESC:
            dp_set_dp_desc(dp, optarg);
            break;

        case OPT_SERIAL_NUM:
            dp_set_serial_num(dp, optarg);
            break;

        case OPT_NO_SLICING:
            dp_set_max_queues(dp, 0);
            break;

        DAEMON_OPTION_HANDLERS

#ifdef HAVE_OPENSSL
        VCONN_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            vconn_ssl_set_ca_cert_file(optarg, true);
            break;
#endif

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: userspace OpenFlow datapath\n"
           "usage: %s [OPTIONS] LISTEN...\n"
           "where LISTEN is a passive OpenFlow connection method on which\n"
       "to listen for incoming connections from the secure channel.\n",
           program_name, program_name);
    vconn_usage(false, true, false);
    printf("\nConfiguration options:\n"
           "  -i, --interfaces=NETDEV[,NETDEV]...\n"
           "                          add specified initial switch ports\n"
           "  -L, --local-port=NETDEV set network device for local port\n"
           "  --no-local-port         disable local port\n"
           "  -d, --datapath-id=ID    Use ID as the OpenFlow switch ID\n"
           "                          (ID must consist of 12 hex digits)\n"
           "  -m, --multiconn         enable multiple connections to the\n"
           "                          same controller.\n"
           "  --no-slicing            disable slicing\n"
           "\nOther options:\n"
           "  -D, --detach            run in background as daemon\n"
           "  -P, --pidfile[=FILE]    create pidfile (default: %s/ofdatapath.pid)\n"
           "  -f, --force             with -P, start even if already running\n"
           "  -v, --verbose=MODULE[:FACILITY[:LEVEL]]  set logging levels\n"
           "  -v, --verbose           set maximum verbosity level\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n",
        ofp_rundir);
    exit(EXIT_SUCCESS);
}

static void matriz_aleatoria_gen(void)
{
	//aleatorizamos la salida
	int i, j, pos; //amount of random numbers that need to be generated
	uint16_t n, check; //variable to store the number in
	//reserva de memoria para cada una de las matrices
	for (pos = 0; pos<16; pos++)
	{
		//reserva de memoria
		if ((Matriz_bc[pos] = xmalloc (sizeof (int)*(dp->ports_num))) == NULL)
			exit(-1); //si no funciona salimos directamente
		
		//generate random numbers:
		for (i=0;i<dp->ports_num;i++)
		{
			do
			{
				n=(rand()%(dp->ports_num));
				//check or number is already used:
				check = 1;
				if (n == dp->ports_num)
					check = 0;
				else
				{
					for (j=0;j<i;j++)
					{
						if (n == Matriz_bc[pos][j]) //if number is already used
						{
							check = 0; //set check to false
							break; //no need to check the other elements of value[]
						}
					}
				}
			} while (check == 0); //loop until new, unique number is found
			Matriz_bc[pos][i]=n; //store the generated number in the array
		}
	}
}