from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_2 import OFPG_ANY
from ryu.ofproto.ofproto_parser import MsgBase, msg
from ryu.lib.mac import is_multicast, haddr_to_str, haddr_to_bin
from ryu.lib.packet import packet, ethernet, llc, arp, pbb, ipv4, tcp
import socket
#from ryu.app.ofctl import api #Obtener objeto datapath a partir de un dpid
#importamos base de tiempo para el los refresco
import time
import threading
import struct
from datetime import datetime

#para la eleccion de caminos
import random

#para hilar
import threading


class ARPPATH_as_a_service(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	TTL_ARBOL = 5
	
	def __init__(self, *args, **kwargs):
		super(ARPPATH_as_a_service, self).__init__(*args, **kwargs)
		#recuperacion
		self.topologia=[]; #Estructura {[ID1,ID2,Puerto]}
		self.arboles={}; #Estructura {"ID_CORE":{[ID1,ID2,Puerto]}}
		self.Time_creacion_arboles={};
		self.TTL_ARBOL = 5
		self.Time_Convergencia = {}
		self.Packet_in = 0
		#self.Packet_in = {}
		
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		print "Switch Conectado id:" + str(datapath.id)
	
	#esto es para tratar esos paquetes una vez conocida la topologia
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		#comprobamos que es lo que tengo
		pkt = packet.Packet(msg.data)
		#controlamos el tipo de mensaje
		eth_pkt = pkt.get_protocol(ethernet.ethernet)
		dst = eth_pkt.dst
		src = eth_pkt.src
		eth_typ = eth_pkt.ethertype
		#cogemos solo el payload
		payload = str(pkt[1:2])
		#print "payload -> "+str(payload)
		#id_switch_envia
		id_switch_packet_in = datapath.id;
		#obtenemos la id_original
		#print "aux: "+str(payload)
		#actualizamios packet in si es valido
		self.Packet_in = int(int(self.Packet_in) + 1);
		try:
			id_switch_original = self.obtener_cadena_8oct(payload[2:34])
			#obtenemos la id_switch_anterior
			id_switch_ant = self.obtener_cadena_8oct(payload[34:66])
			#puerto_salida
			out_port = self.obtener_cadena_8oct(payload[66:98])
			#puerto entrada
			inport = msg.match['in_port']
			#detectamos si es el primer paquete o no
			pos_pkt = self.obtener_cadena_8oct(payload[98:130])
			
			#Link Descubierto!!!
			#print "Posicion del paquete: " + str(pos_pkt)
			#print "["+str(id_switch_packet_in)+","+str(id_switch_ant)+","+str(inport)+"],["+str(id_switch_ant)+","+str(id_switch_packet_in)+","+str(out_port)+"]"

			#sino es el primero debemos tenerlo en cuenta para la topologia
			self.crear_arbol(id_switch_packet_in, id_switch_ant, inport, out_port, id_switch_original, pos_pkt)
			#actualizamios packet in si es valido
			# if self.Packet_in.has_key(id_switch_original):
				# self.Packet_in[id_switch_original] = int(int(self.Packet_in[id_switch_original]) + 1);
			# else:
				# self.Packet_in[id_switch_original] = 1;
		except ValueError:
			return;
	################################################################################################	
	def crear_topologia(self, id_switch_A, id_switch_B, PORT_AB, PORT_BA, id_switch_original):
		encontradoAB = 0; 
		encontradoBA = 0;
		array_AB = [id_switch_A, id_switch_B, PORT_AB];
		array_BA = [id_switch_B, id_switch_A, PORT_BA];

		if (len(self.topologia) == 0):
			self.topologia.append(array_AB)
			self.topologia.append(array_BA)
		else:
			for pos in range(0, len(self.topologia)):
				if (self.topologia[pos][0] == id_switch_A and self.topologia[pos][1] == id_switch_B):
					self.topologia[pos] = array_AB;
					encontradoAB = 1
				elif (self.topologia[pos][0] == id_switch_B and self.topologia[pos][1] == id_switch_A):
					self.topologia[pos] = array_BA;
					encontradoBA = 1
			if encontradoAB == 0:
				self.topologia.append(array_AB)	
			if encontradoBA == 0:
				self.topologia.append(array_BA)	
			if encontradoBA == 0 or encontradoAB == 0:
				#actualizamos los contadores
				print str(id_switch_original) + "|" + str(datetime.now() - self.Time_Convergencia[id_switch_original]) + "|" + str(self.Packet_in)
				#print str(id_switch_original) + "|" + str(datetime.now() - self.Time_Convergencia[id_switch_original]) + "|" + str(self.Packet_in[id_switch_original])
				#print str(self.topologia)+str("\n"))
	
	################################################################################################
	def crear_arbol(self,id_switch_A, id_switch_B, PORT_AB, PORT_BA, id_switch_original, pos_pkt):
	
		encontradoAB = 0; 
		encontradoBA = 0;
		array_AB = [id_switch_A, id_switch_B, PORT_AB];
		array_BA = [id_switch_B, id_switch_A, PORT_BA];
	
		if pos_pkt == 1:
			#Antes de nada comprobamos el arbol no ha caducado
			if (self.Time_creacion_arboles.has_key(id_switch_original)):
				if self.Time_creacion_arboles[id_switch_original] <= time.time() :
					#print "Limpiamos Arbolcon core Switch: "+str(id_switch_original)+" en el momento "+ str(time.time())
					print "Arbol nodo: " +str(id_switch_original)+"\n"+str(self.arboles[id_switch_original])
					del self.Time_creacion_arboles[id_switch_original]
					del self.arboles[id_switch_original]
			#una vez nos hemos asegurado que los arboles no se pisan.
			#Estructura {"ID_CORE":{[ID1,ID2,Puerto]}}
			if (self.arboles.has_key(id_switch_original)): #si existe el arbol lo vamos actualizando
				for pos in range(0, len(self.arboles[id_switch_original])):
					if (self.arboles[id_switch_original][pos][0] == id_switch_A and self.arboles[id_switch_original][pos][1] == id_switch_B):
						self.arboles[id_switch_original][pos] = array_AB;
						encontradoAB = 1
					elif (self.arboles[id_switch_original][pos][0] == id_switch_B and self.arboles[id_switch_original][pos][1] == id_switch_A):
						self.arboles[id_switch_original][pos] = array_BA;
						encontradoBA = 1
				if encontradoAB == 0:
					self.arboles[id_switch_original].append(array_AB)	
				if encontradoBA == 0:
					self.arboles[id_switch_original].append(array_BA)
			else:
				print "Creamos arbol nuevo con core Switch: "+str(id_switch_original)+" en el momento "+ str(time.time())
				#indicamos el tiempo en que se crea el arbol
				self.Time_creacion_arboles[id_switch_original] = time.time() + self.TTL_ARBOL
				#introducimos el link para comenzar el arbol
				self.arboles[id_switch_original] = []
				self.arboles[id_switch_original].append(array_AB)
				self.arboles[id_switch_original].append(array_BA)
				#reiniciamos contadores
				self.Packet_in = 1;
				#self.Packet_in[id_switch_original] = 1;
				self.Time_Convergencia[id_switch_original] = datetime.now();
				#print self.arboles[id_switch_original]
		#pasamos a procesar la topologia
		self.crear_topologia(id_switch_A, id_switch_B, PORT_AB, PORT_BA, id_switch_original)	
					
	################################################################################################
	def obtener_cadena_8oct (self, datos):
		aux = str(datos[30:32])+str(datos[26:28])+str(datos[22:24])+str(datos[18:20])+str(datos[14:16])+str(datos[10:12])+str(datos[6:8])+str(datos[2:4]);
		return int(aux,16);