# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp
from ryu.lib.packet import ether_types


nextLoad = 5
paths = [0,0,0,0,0]


class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.mac_to_port = {}

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
	                                             actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
        	                            priority=priority, match=match,
                	                    instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                        	            match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
	                              ev.msg.msg_len, ev.msg.total_len)
#		paths = [0, 0, 0, 0, 0]
#		nextLoad = 5
		global paths
		global nextLoad
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype != ether_types.ETH_TYPE_ARP:
			return
		thisArp = pkt.get_protocols(arp.arp)[0]
		dst = eth.dst
		src = eth.src
		dstIP = thisArp.dst_ip
		srcIP = thisArp.src_ip

		if(dstIP != '10.0.0.10' or
	          (in_port != 1 and in_port != 2 and in_port != 3 and in_port != 4)):
			#handle arps from 5 and 6
			if dstIP == '10.0.0.1':
				mac = '00:00:00:00:00:01'
			elif dstIP == '10.0.0.2':
				mac = '00:00:00:00:00:02'
			elif dstIP == '10.0.0.3':
				mac = '00:00:00:00:00:03'
			else:
				mac = '00:00:00:00:00:04'
			e = ethernet.ethernet(dst=src, src=mac, ethertype=ether_types.ETH_TYPE_ARP)
			a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2, src_mac=mac, 
			            src_ip=dstIP, dst_mac=src, dst_ip=srcIP)
			p = packet.Packet()
			p.add_protocol(e)
			p.add_protocol(a)
			p.serialize()

			actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
			out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
		                                  in_port=in_port, actions=actions, data=p.data)
			datapath.send_msg(out)
			return

		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})

		print(dpid, src, dst, in_port, srcIP, dstIP)

		if paths[in_port] != 0:
			out_port = paths[in_port]
		else:
			out_port = nextLoad
			if nextLoad == 5:
				nextLoad = 6
			else:
				nextLoad = 5
#		out_port = 5
#		targIP = '10.0.0.5'
		targIP = '10.0.0.{}'.format(out_port)
		actions = [parser.OFPActionSetField(ipv4_dst=targIP)]
		actions += [parser.OFPActionOutput(out_port)]
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=in_port, ipv4_dst='10.0.0.10')
		self.add_flow(datapath, 1, match, actions)

		actions = [parser.OFPActionSetField(ipv4_src='10.0.0.10')]
		actions += [parser.OFPActionOutput(in_port)]
		match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=out_port, ipv4_dst=srcIP)
		self.add_flow(datapath, 1, match, actions)

#		targEth = '00:00:00:00:00:05'
		targEth = '00:00:00:00:00:0{}'.format(out_port)
		e = ethernet.ethernet(dst=src, src=targEth, ethertype=ether_types.ETH_TYPE_ARP)
		a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2, src_mac=targEth, 
		            src_ip='10.0.0.10', dst_mac=src, dst_ip=srcIP)
		p = packet.Packet()
		p.add_protocol(e)
		p.add_protocol(a)
		p.serialize()

		actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
		out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
	                                  in_port=in_port, actions=actions, data=p.data)
		datapath.send_msg(out)
