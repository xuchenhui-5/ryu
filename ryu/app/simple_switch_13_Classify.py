# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
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
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp

TCP = tcp.tcp.__name__
ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__
UDP = udp.udp.__name__
ICMP=icmp.icmp.__name__

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}
        self.sw = {}

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
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                hard_timeout=20,  #table_id=1,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        src_eth="e6:47:59:f2:62:cb"


        header_list = dict(
            (p.protocol_name, p) for p in pkt.protocols if type(p) != str)
        if ARP in header_list:
            self.arp_table[header_list[ARP].src_ip] = src  #ARP learning

            #ipdst=header_list[ARP].dst_ip

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        if src not in self.mac_to_port[dpid]:#record only one in_port
            self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            if self.arp_handle(header_list, datapath, in_port):
                print "ARP_PROXY13"
                return None
            else:
                out_port = ofproto.OFPP_FLOOD
                print "flood!"

        #mark label for tcp
        # for pack in header_list:
        #     self.logger.info("packType:%s", pack)
        #     #for p in pkt.protocols
        #
        #     if pack == TCP:
        #         actions = [parser.OFPActionOutput(out_port), parser.OFPActionSetField(ip_dscp=48),
        #                    parser.OFPActionSetQueue(7)]
        #         if out_port != ofproto.OFPP_FLOOD:
        #             match = parser.OFPMatch(in_port=in_port, eth_dst=dst, ip_proto=6, eth_type=0x0800)
        #             self.mark_tcp(datapath, 1, match, actions)
        #         data = None
        #         if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #             data = msg.data
        #
        #         out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                         in_port=in_port, actions=actions, data=data)
        #         datapath.send_msg(out)
        #
        #     elif pack == UDP:
        #         actions = [parser.OFPActionOutput(out_port), parser.OFPActionSetField(ip_dscp=1),
        #                    parser.OFPActionSetQueue(0)]
        #         if out_port != ofproto.OFPP_FLOOD:
        #             match = parser.OFPMatch(in_port=in_port, eth_dst=dst, ip_proto=17, eth_type=0x0800)
        #             self.mark_tcp(datapath, 1, match, actions)
        #         data = None
        #         if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #             data = msg.data
        #
        #         out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                         in_port=in_port, actions=actions, data=data)
        #         datapath.send_msg(out)
        #
        #     elif pack==ICMP:
        #         #actions = [parser.OFPActionOutput(out_port),parser.OFPActionSetField(ip_dscp=2)]
        #         actions = [parser.OFPActionOutput(out_port)]
        #         # install a flow to avoid packet_in next time
        #         if out_port != ofproto.OFPP_FLOOD:
        #             #actions = [parser.OFPActionOutput(out_port),parser.OFPActionSetQueue(0)]
        #             match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
        #             self.add_flow(datapath, 1, match, actions)
        #actions = [parser.OFPActionOutput(out_port)]
        for pack in header_list:
            if pack!=ARP and dpid==1 and src==src_eth:
                print'deal group'
                self.add_group_table(datapath)
                actions = [parser.OFPActionGroup(group_id=50)]
            else:
                actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def mark_tcp(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                hard_timeout=15,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def arp_handle(self, header_list, datapath, in_port):
        header_list = header_list
        datapath = datapath
        in_port = in_port

        if ETHERNET in header_list:
            eth_dst = header_list[ETHERNET].dst
            eth_src = header_list[ETHERNET].src

        if eth_dst == ETHERNET_MULTICAST and ARP in header_list:
            arp_dst_ip = header_list[ARP].dst_ip
            if (datapath.id, eth_src, arp_dst_ip) in self.sw:  #Break the loop
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=[], data=None)
                    datapath.send_msg(out)
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        if ARP in header_list:
            hwtype = header_list[ARP].hwtype
            proto = header_list[ARP].proto
            hlen = header_list[ARP].hlen
            plen = header_list[ARP].plen
            opcode = header_list[ARP].opcode

            arp_src_ip = header_list[ARP].src_ip
            arp_dst_ip = header_list[ARP].dst_ip

            actions = []

            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:  #arp reply
                    actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))
                    ARP_Reply = packet.Packet()
                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype=header_list[ETHERNET].ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))
                    ARP_Reply.serialize()
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=datapath.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    return True
        return False

    #add group table
    def add_group_table(self,datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        port_1=3
        actions_1 = [ofp_parser.OFPActionOutput(port_1)]
        port_2 = 2
        actions_2 = [ofp_parser.OFPActionOutput(port_2)]
        weight_1 = 50
        weight_2 = 50

        watch_port = ofproto_v1_3.OFPP_ANY
        watch_group = ofproto_v1_3.OFPQ_ALL

        buckets = [ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
                   ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]
        group_id = 50
        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPFC_ADD,
                                     ofp.OFPGT_SELECT, group_id, buckets)
        datapath.send_msg(req)