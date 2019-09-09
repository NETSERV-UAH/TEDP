from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_2 import OFPG_ANY
from ryu.ofproto.ofproto_parser import MsgBase, msg
from ryu.lib.mac import is_multicast, haddr_to_str, haddr_to_bin
from ryu.lib.packet import packet, ethernet, llc, arp, pbb, ipv4, tcp
from ryu.lib import hub
import socket
#from ryu.app.ofctl import api #Obtener objeto datapath a partir de un dpid
#importamos base de tiempo para el los refresco
import time
import struct
from datetime import datetime

#para la eleccion de caminos
import random

class ARPPATH_as_a_service(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	
	def __init__(self, *args, **kwargs):
		super(ARPPATH_as_a_service, self).__init__(*args, **kwargs)
		#recuperacion
		self.switches = {}; #asociacion de la ID del switch con su datapath
		self.mac_switches = {}; #Asociacion de la ID del switch con sus mac's
		self.topologia=[]; #Estructura {[ID1,ID2,Puerto]}
		self.arboles={}; #Estructura {"ID_CORE":{[ID1,ID2,Puerto]}}
		self.Time_creacion_arboles={};
		self.TTL_ARBOL = 50;
		self.Time_wait = 2;
		self.ultimo_stat = time.time();
		self.apas_event = hub.Event();
		self.threads=[hub.spawn(self.descubrir_topologia)]
		self.time_convergence = 0; #contador para tiempo de convergencia
		self.flow_mod = 0; #contador para numero de paquetes flow_mod
		self.packet_in = 0; #contador para numero de paquetes packet_in
		self.packet_out = 0; #contador para numero de paquetes packet_out
		self.puerto_confirmados={} #conocer que puertos ya han recibido packet_in
	
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		self.switches[datapath.id] = datapath;
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser;
		#metemos regla para que todo suba al controler
		match = parser.OFPMatch(eth_type=0x86dd)
		actions = [parser.OFPActionOutput(0, ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions, 0, 0, 0, 0)
		print "switch detectado: "+str(datapath.id)+" Enviamos regla generica"
		#Necesitamos conocer al menos una de las mac del switch para los paquetes ARPPATH_as_a_service
		#asi que enviamos una peticion de informacion segun se levante cada uno de los switches
		self.send_port_desc_stats_request(datapath)
		self.apas_event.set()


	#esto es para tratar esos paquetes una vez conocida la topologia
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		#comprobamos que es lo que tengo
		pkt = packet.Packet(msg.data)
		#print "ha llegado un packet in desde: "+str(datapath.id)
		#atencion solo tratamos los arp
		#Primero Bloquear nuevos paquetes
		#obtengo los elementos de bloqueo
		pkt = packet.Packet(msg.data)
		eth_pkt = pkt.get_protocol(ethernet.ethernet)
		dst = eth_pkt.dst
		src = eth_pkt.src
		eth_typ = eth_pkt.ethertype
		if (eth_typ == 0x0806):
			arp_pkt = pkt.get_protocol(arp.arp)
			arp_sha = arp_pkt.src_mac
			opcode = arp_pkt.opcode
			#id_switch_envia packet in
			id_switch_packet_in = datapath.id;
			#puerto entrada
			inport = msg.match['in_port']
			#generar el arbol y la topologia
			#empezamos obteniendo el core del arbol
			id_core = 0;
			for id_switch in self.mac_switches.keys():
				if arp_sha == self.mac_switches[id_switch][0]:
					id_core = id_switch
					break;
			#id witch anterior
			id_switch_ant = 0
			for id_switch in self.mac_switches.keys():
				if src == self.mac_switches[id_switch][0]:
					id_switch_ant = id_switch
					break;
			#self.packet_in = int(self.packet_in) + 1;
			#Comprobar que el puerto no ha sido ya recibido
			if (self.puerto_entrada_ok(id_switch_packet_in, inport, id_core, id_switch) == 1): #si no tenemos ese puerto es no repetido
				match = parser.OFPMatch(eth_dst = dst, eth_type = 2054, arp_sha = arp_sha, arp_tha = arp_sha)
				actions = []
				##actions.append(parser.OFPActionSetField(arp_op=arp.ARP_REPLY)) #le indicamos que con el macth anterior modifique este dato
				actions.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)) #debemos cambiar la accion para que nos la mande al controler
				self.add_flow(datapath, 1, match, actions, 10, 0, 0, 1)
				if id_switch_ant != 0 and id_core != 0 and id_switch_packet_in != id_switch_ant: #si es un nodo de nuestra red, comprobacion anti host
					#Link Descubierto!!!
					#print "Core: "+str(id_core)+" Link -> ["+str(id_switch_packet_in)+","+str(id_switch_ant)+","+str(inport)+"]"
					#sino es el primero debemos tenerlo en cuenta para la topologia
					self.crear_arbol(id_switch_packet_in, id_switch_ant, inport, id_core);
					#aumentamos el contador de packet_in
					self.packet_in = int(self.packet_in) + 1;
				# else:
					# print "Core->"+str(id_core)+", id_switch_ant->"+str(id_switch_ant)+", id_switch_packet_in->"+str(id_switch_packet_in)
			else:
				# comprobamos si todos los puertos del switch han sido completados
				if (len(self.puerto_confirmados[id_core][id_switch_packet_in]) == len(self.mac_switches[id_switch_packet_in])):
					#si ya hemos completado todos los puertos del switch debemos enviar un 0
					match = parser.OFPMatch(eth_dst = dst, eth_type = 2054, arp_sha = arp_sha, arp_tha = arp_sha)
					actions = []
					##actions.append(parser.OFPActionSetField(arp_op=arp.ARP_REPLY)) #le indicamos que con el macth anterior modifique este dato
					actions.append(parser.OFPActionOutput(0)) #debemos cambiar la accion para que nos la mande al controler
					self.add_flow(datapath, 1, match, actions, 20, 0, 0, 1)
					self.packet_out = int(self.packet_out) + 1;
			
	#cogemos el evento generado por la respuesta de informacion de los puertos
	@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
	def port_desc_stats_reply_handler(self, ev):
		ports = []
		for p in ev.msg.body:
			ports.append(p.hw_addr)
		self.mac_switches[int(ev.msg.datapath.id)] = ports;
		self.ultimo_stat = time.time();
		
		
	################################################################################################	
	def crear_topologia(self, id_switch_A, id_switch_B, PORT_AB):
		encontradoAB = 0; 
		array_AB = [id_switch_A, id_switch_B, PORT_AB];
		if (len(self.topologia) == 0):
			self.topologia.append(array_AB)
		else:
			for pos in range(0, len(self.topologia)):
				if (self.topologia[pos][0] == id_switch_A and self.topologia[pos][1] == id_switch_B):
					self.topologia[pos] = array_AB;
					encontradoAB = 1
					break;
			if encontradoAB == 0:
				self.topologia.append(array_AB)
				print str(datetime.now() - self.time_convergence)+" us|"+str(self.packet_in)+"|"+str(self.flow_mod)+"|"+str(self.packet_out)
				#print ("Elemento insertado: ")+str(array_AB)
				#print str(self.topologia)
	################################################################################################
	def crear_arbol(self,id_switch_A, id_switch_B, PORT_AB, id_switch_original):
		encontrado = 0;
		pos_pkt = 1;
		array_AB = [id_switch_A, id_switch_B, PORT_AB];
		#Antes de nada comprobamos el arbol no ha caducado
		if (self.Time_creacion_arboles.has_key(id_switch_original)):
			if self.Time_creacion_arboles[id_switch_original] <= time.time() :
				#print "Limpiamos Arbolcon core Switch: "+str(id_switch_original)+" en el momento "+ str(time.time())
				#print "Arbol nodo: " +str(id_switch_original)+"\n"+str(self.arboles[id_switch_original])
				del self.Time_creacion_arboles[id_switch_original]
				del self.arboles[id_switch_original]
				#reiniciamos el elementos de puertos
				if self.puerto_confirmados.has_key(id_core):
					if self.puerto_confirmados[id_core].has_key(id_switch_packet_in):
						del self.puerto_confirmados[id_core][id_switch_packet_in]; #si existe lo reiniciamos
		#una vez nos hemos asegurado que los arboles no se pisan.
		#Estructura {"ID_CORE":{[ID1,ID2,Puerto]}}
		
		if (self.arboles.has_key(id_switch_original)): #si existe el arbol lo vamos actualizando
			#comprobamos si existen elementos iguales
			if (not array_AB in self.arboles[id_switch_original]):
				#sino tenemos elementos iguales entonces vemos si el enlace es valido
				for pos in range(0, len(self.arboles[id_switch_original])):
					if (self.arboles[id_switch_original][pos][0] == id_switch_B and self.arboles[id_switch_original][pos][1] == id_switch_A): #si es inversa nos vale
						encontrado = 0; #si es un elemento invertido nos vale
						break;
					elif (self.arboles[id_switch_original][pos][0] == id_switch_A): #si el nodo esta correcto nos vale
						encontrado = 1;
			else:
				encontrado = 1;
		else:
			#print "Creamos arbol nuevo con core Switch: "+str(id_switch_original)+" en el momento "+ str(time.time())
			#indicamos el tiempo en que se crea el arbol
			self.Time_creacion_arboles[id_switch_original] = time.time() + self.TTL_ARBOL
			#introducimos el link para comenzar el arbol
			self.arboles[id_switch_original] = [];
			encontrado = 0;
					
		if encontrado == 0:
			self.arboles[id_switch_original].append(array_AB)
			#print ("Elemento insertado: ")+str(array_AB)
			self.arboles[id_switch_original] = sorted(self.arboles[id_switch_original], key=lambda x: x[0] )
			#print self.arboles[id_switch_original]
		#pasamos a procesar la topologia
		self.crear_topologia(id_switch_A, id_switch_B, PORT_AB)	
	
	################################################################################################
	#enviamos features_request
	def send_port_desc_stats_request(self, datapath):
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
		datapath.send_msg(req)				
	
	################################################################################################
	def descubrir_topologia(self):
		#print "entramos en bucle";
		id_core = 1;
		while 1:
			#lanzamos un hilo para generar los paquetes de forma aleatoria
			if (int(time.time()) - int(self.ultimo_stat) > int(self.Time_wait)):
				print "Iniciamos la exploracion de topologia: "+str(id_core)
				self.ultimo_stat = time.time()#modificamos para evitar exploraciones continuas
				#comenzamos con el proceso
				while (not self.mac_switches.has_key(id_core)):
					id_core = id_core + 1;
					if id_core == 99: #si llegamos al ultimo tor empezamos por el principio otra vez
						id_core = 1;
				#iniciamos los contadores de nuevo
				self.flow_mod = 0; #contador para numero de paquetes flow_mod
				self.packet_in = 0; #contador para numero de paquetes packet_in
				self.packet_out = 0; #contador para numero de paquetes packet_out
				self.time_convergence = datetime.now(); #int(round(time.time() * 1000));
				#preinstalamos las reglas necesarias para llevar acabo la exploracion
				self.install_initial_rules(id_core);
				#generamos y enviamos el paquete al core del arbol
				self.crear_y_enviar_paquete(id_core);
				#posicionamos para llevar acabo la siguiente exploracion
				id_core = id_core + 1; #para enviar al siguiente core
				time.sleep(self.TTL_ARBOL); #para dejar margen
			time.sleep(1);
		
	################################################################################################
	#Instalacion Reglas openflow iniciales
	def install_initial_rules(self, id_core):
		for switch_id in self.switches.keys():
			#print "vamos a enviar un flow_mod al switch: "+str(switch_id)
			datapath = self.switches[switch_id];
			parser = self.switches[switch_id].ofproto_parser;
			ofproto = datapath.ofproto;
			#reamos el match
			match = parser.OFPMatch(eth_dst = "FF:FF:FF:FF:FF:FF", eth_type = 2054, arp_sha = str(self.mac_switches[id_core][0]), arp_tha = str(self.mac_switches[id_core][0]));
			#insertamos todas las acciones
			actions = []
			#solo controlamos la doble puesto que los switches tienen una regla generica que les dice que nos mande todo al controller
			if switch_id != id_core: #solo enviamos estas reglas a los nodos no cores del arbol
				#primero al controler
				actions.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER))
				#segundo modificamos el elemento que queremos
				actions.append(parser.OFPActionSetField(eth_src=str(self.mac_switches[switch_id][0]))) #le indicamos que con el macth anterior modifique este dato
				#tercero lo reenivamos por todos los puertos menos el de entrada
				actions.append(parser.OFPActionOutput(ofproto.OFPP_ALL))
				#cuarto lo reenivamos por el de entrada
				actions.append(parser.OFPActionOutput(ofproto.OFPP_IN_PORT))
				# print "actions:\t "+str(actions)
				# print "match:\t "+str(match)
				print("Se instalaron las reglas correctamente en el nodo "+str(switch_id))
			else:
				print("Solo se instala envio al controller")
				#primero al controler
				actions.append(parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER))
			self.add_flow(self.switches[switch_id], 1, match, actions, 10, 0, 0, 0)
			#time.sleep(0.5); #para dar tiempo a instalar las reglas
	
	#creamos y generamos el paquete arp de exploracion
	def crear_y_enviar_paquete(self, id_core):
		#creamos el paquete
		e = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',src=str(self.mac_switches[id_core][0]),ethertype=0x0806)
		a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=1, 
			src_mac=str(self.mac_switches[id_core][0]), src_ip='0.0.0.0',dst_mac=str(self.mac_switches[id_core][0]), dst_ip='0.0.0.0')
		p = packet.Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()
		#enpaquetamos en PacketIN
		parser = self.switches[id_core].ofproto_parser;
		actions = [parser.OFPActionOutput(self.switches[id_core].ofproto.OFPP_ALL)]
		out = parser.OFPPacketOut(datapath = self.switches[id_core], buffer_id = self.switches[id_core].ofproto.OFP_NO_BUFFER, in_port=0, actions=actions, data=p.data)
		self.switches[id_core].send_msg(out)
		#aumentamos el contador de packet_out
		self.packet_out = int(self.packet_out) + 1;
		print "Enviado el mensaje correctamente"
	
	def puerto_entrada_ok(self, id_switch_packet_in, inport, id_core, id_switch_ant):
		if self.puerto_confirmados.has_key(id_core):
			if self.puerto_confirmados[id_core].has_key(id_switch_packet_in):
				if (inport in self.puerto_confirmados[id_core][id_switch_packet_in]):
					return 0;
				else:
					self.puerto_confirmados[id_core][id_switch_packet_in].append(inport);
			else:
				self.puerto_confirmados[id_core][id_switch_packet_in] = [] #creamos el array
				self.puerto_confirmados[id_core][id_switch_packet_in].append(inport); #insertamos el nuevo elemento
				return 1;
		
		#si no existe se inserta y se devuelve 1
		else:
			self.puerto_confirmados[id_core] = {} #creamos el diccionario
			self.puerto_confirmados[id_core][id_switch_packet_in] = [] #creamos el array 
			self.puerto_confirmados[id_core][id_switch_packet_in].append(inport) #insertamos el puerto
		
		return 1;
	################################################################################################
	#enviamos flow_mod
	def add_flow(self, datapath, priority, match, actions, idle_timeout, hard_timeout, table_id = 0, command=0):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
			table_id=table_id, command=command)
		#print str(mod)
		datapath.send_msg(mod)
		#aumentamos el contador de Flow_mod
		self.flow_mod = int(self.flow_mod) + 1;