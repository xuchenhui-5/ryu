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
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import hub

from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from collections import defaultdict
from ryu.topology.api import get_switch,get_link
from ryu.topology import event,switches
from ryu.lib import stplib
from ryu.lib import dpid as dpid_lib
import math
import random


ARP = arp.arp.__name__
ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"

adjacency = defaultdict(lambda: defaultdict(lambda: None))
path_map = defaultdict(lambda: defaultdict(lambda: (None, None)))
sws = []
sw_Num=[]
switches={}
mac_map={}
i=0

weight={}
last_link={}
dis_error={} #keep the minimum dscretization error
lin_error={} #discretization error of a link
dis_delay={} #delay is discretized
S=[]
dist=[]
pre=[]
r=5 #delay reqirement
MAX_NUM=10000
edge=[
    [0,1,1,1,MAX_NUM],
    [1,0,1,MAX_NUM,1],
    [1,1,0,MAX_NUM,MAX_NUM],
    [1,MAX_NUM,MAX_NUM,0,1],
    [MAX_NUM,1,MAX_NUM,1,0],
]
delay=[]
cost=[]

def _get_raw_path(src, dst):
    """
    Get a raw path (just a list of nodes to traverse)
    """
    if len(path_map) == 0: _dijkstra_paths()
    if src is dst:
        # We're here!
        return []
    # S=int(src[-1:])
    # D=int(dst[-1:])
    # S=(mac_map[src])[0]
    # D=(mac_map[dst])[0]

    if path_map[src][dst][0] is None:
        return None
    intermediate = path_map[src][dst][1]
    if intermediate is None:
        # Directly connected
        return []
    return _get_raw_path(src, intermediate) + [intermediate] + \
           _get_raw_path(intermediate, dst)

def _get_path(src, dst, first_port, final_port):
    """
    Gets a cooked path -- a list of (node,in_port,out_port)
    """
    # Start with a raw path...
    # print src
    # print dst
    if src == dst:
        path = [src]
    else:
        path = _get_raw_path(src, dst)
        if path is None: return None
        path = [src] + path + [dst]

    # Now add the ports
    r = []
    in_port = first_port
    for s1, s2 in zip(path[:-1], path[1:]):
        # S1=int(s1[-1:])
        # S2=int(s2[-1:])
        # S1=mac_map[s1]
        # S2=mac_map[s2]
        out_port = adjacency[s1][s2]
        r.append((s1, in_port, out_port))
        in_port = adjacency[s2][s1]
    r.append((dst, in_port, final_port))
    #print 'R is %s' % r
    return r

def _dijkstra_paths():
    #sws = switches.keys()
    #print sws
    path_map.clear()
    for k in sws:
        for j, port in adjacency[k].iteritems():
            if port is None:
                continue
            path_map[k][j] = (1, None)
        path_map[k][k] = (0, None)
        #print adjacency[k]

    for t in sws:
        final_point = []
        final_point.append(t)
        for i in range(len(sws) - 1):
            min_path = 999
            for p in sws:
                if p not in final_point:
                    if path_map[t][p][0] is not None and path_map[t][p][0] < min_path:
                        min_path = path_map[t][p][0]
                        temp = p
            final_point.append(temp)
            for m in sws:
                if m not in final_point:
                    if path_map[t][m][0] is None and path_map[t][temp][0] is not None and path_map[temp][m][
                        0] is not None:
                        path_map[t][m] = (path_map[t][temp][0] + path_map[temp][m][0], temp)
                    elif path_map[t][temp][0] is not None and path_map[temp][m][0] is not None and path_map[t][m][
                        0] is not None:
                        if path_map[t][temp][0] + path_map[temp][m][0] < path_map[t][m][0]:
                            path_map[t][m] = (path_map[t][temp][0] + path_map[temp][m][0], temp)
    print path_map

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #_CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}
        self.sw = {}
        self.port_tx = {}
        self.datapaths = {}
        self.datapath_list={}
        self.topology_api_app=self
        self.monitor_thread = hub.spawn(self.monitor)
        self.mark=True
        #self.stp = kwargs['stplib']
        #
        # config={dpid_lib.str_to_dpid('0000000000000001'):
        #             {'bridge':{'priority':0x8000}},
        #         dpid_lib.str_to_dpid('0000000000000002'):
        #             {'bridge':{'priority':0x9000}},
        #         dpid_lib.str_to_dpid('0000000000000003'):
        #             {'bridge':{'priority':0xa000}},
        #         dpid_lib.str_to_dpid('0000000000000004'):
        #             {'bridge':{'priority':0xb000}},
        #         dpid_lib.str_to_dpid('0000000000000005'):
        #             {'bridge':{'priority':0xc000}},
        #         dpid_lib.str_to_dpid('0000000000000006'):
        #             {'bridge':{'priority':0xd000}},
        #         dpid_lib.str_to_dpid('0000000000000007'):
        #             {'bridge':{'priority':0xe000}},
        #         dpid_lib.str_to_dpid('0000000000000008'):
        #             {'bridge':{'priority':0xf000}}}
        #
        # self.stp.set_config(config)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        switches[datapath.id]=datapath

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

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                #hard_timeout=20,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    #@set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype==35020:
            return
        if eth.ethertype==34525:
            return

        dst = eth.dst
        src = eth.src
        # ip_src=None
        # ip_dst =None
        # if pkt.get_protocol(arp.arp):
        #     arp_ip = pkt.get_protocol(arp.arp)
        #     ip_src = arp_ip.src_ip
        #     ip_dst = arp_ip.dst_ip
        #
        # if ip_src is None:
        #     if pkt.get_protocol(ipv4.ipv4):
        #         ip=pkt.get_protocol(ipv4.ipv4)
        #         ip_src=ip.src
        #         ip_dst=ip.dst

        loc=('00-00-00-00-00-0'+str(datapath.id),in_port)
        oldloc=mac_map.get(src)
        if oldloc is None:
            mac_map[src]=loc
        elif src not in mac_map:
            mac_map[src]=loc

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        header_list = dict(
            (p.protocol_name, p) for p in pkt.protocols if type(p) != str)
        if ARP in header_list:
            self.arp_table[header_list[ARP].src_ip] = src  # ARP learning


        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # learn a mac address to avoid FLOOD next time.
        if src not in self.mac_to_port[dpid]:  #record only one in_port
            self.mac_to_port[dpid][src] = in_port
        #self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

            temp_src=mac_map[src]
            temp_dst=mac_map[dst]

            self.install_path(temp_src[0],temp_dst[0], temp_src[1], temp_dst[1], ev)
            #self.logger.info("out_port: %s", out_port)
        else:
            if self.arp_handler(header_list, datapath, in_port, msg.buffer_id):
                # 1:reply or drop;  0: flood
                print "ARP_PROXY_13"
                return None
            else:
                out_port = ofproto.OFPP_FLOOD
                print"flood!"
        # else:
        #     out_port = ofproto.OFPP_FLOOD
        #     print"flood!"

        actions = [parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            #self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id == 1:
                self.datapaths[datapath.id] = datapath
            if not datapath.id in self.datapath_list:
                self.datapath_list[datapath.id]=datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.send_port_stats_request(dp)
            hub.sleep(1)

    #port stats
    def send_port_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        ports = []
        p=[]
        bw=-1
        # for stat in ev.msg.body:
        #     ports.append('port_no=%d ' 'rx_packets=%d tx_packets=%d '
        #                  'rx_bytes=%d tx_bytes=%d ''rx_dropped=%d tx_dropped=%d '
        #                  'rx_errors=%d tx_errors=%d '
        #                  'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
        #                  'collisions=%d duration_sec=%d duration_nsec=%d' %
        #                  (stat.port_no,
        #                   stat.rx_packets, stat.tx_packets,
        #                   stat.rx_bytes, stat.tx_bytes,
        #                   stat.rx_dropped, stat.tx_dropped,
        #                   stat.rx_errors, stat.tx_errors,
        #                   stat.rx_frame_err, stat.rx_over_err,
        #                   stat.rx_crc_err, stat.collisions,
        #                   stat.duration_sec, stat.duration_nsec))
        for stat in ev.msg.body:
            ports.append('port_no=%d ' 'rx_packets=%d tx_packets=%d '
                         'rx_bytes=%d tx_bytes=%d ''rx_dropped=%d tx_dropped=%d '
                         'rx_errors=%d tx_errors=%d ' %
                         (stat.port_no,
                          stat.rx_packets, stat.tx_packets,
                          stat.rx_bytes, stat.tx_bytes,
                          stat.rx_dropped, stat.tx_dropped,
                          stat.rx_errors, stat.tx_errors))
            if not stat.port_no in self.port_tx.keys():
                self.port_tx[stat.port_no] = stat.tx_bytes
                print'Add new port %d' % stat.port_no
            else:
                if stat.tx_bytes != self.port_tx[stat.port_no]:
                    count = stat.tx_bytes - self.port_tx[stat.port_no]
                    if stat.port_no==3:
                        bw = count * 8 / 1000000
                        if bw>0:
                            print'port %d : current bw is %d Mb' % (stat.port_no, bw)
                    self.port_tx[stat.port_no] = stat.tx_bytes
                else:
                    #print "continue"
                    continue
        #install the oprimization path

        if bw>=10 and self.mark==True:
            hub.sleep(20)
            # '''
            # for s8-h6
            # '''
            # sw1="00-00-00-00-00-01"
            # sw2="00-00-00-00-00-02"
            # sw3="00-00-00-00-00-03"
            # sw5="00-00-00-00-00-05"
            # sw7="00-00-00-00-00-07"
            # eth_src3="00:00:00:00:00:03"
            # eth_src4="00:00:00:00:00:04"
            #
            # _sw=[sw1,sw2,sw7]
            # for temp_sw in _sw:
            #     ID=int(temp_sw[-1:])
            #     if ID==1:
            #         in_port_temp=6
            #         self.delete_old_flow(temp_sw,eth_src3,in_port_temp)
            #     elif ID==2:
            #         in_port_temp=1
            #         self.delete_old_flow(temp_sw,eth_src3,in_port_temp)
            #     elif ID==7:
            #         in_port_temp=2
            #         self.delete_old_flow(temp_sw,eth_src3,in_port_temp)
            # for temp_sw in _sw:
            #     ID=int(temp_sw[-1:])
            #     if ID==1:
            #         in_port_temp=2
            #         self.delete_old_flow(temp_sw,eth_src4,in_port_temp)
            #     if ID==2:
            #         in_port_temp=2
            #         self.delete_old_flow(temp_sw,eth_src4,in_port_temp)
            #     if ID==7:
            #         in_port_temp=6
            #         self.delete_old_flow(temp_sw,eth_src4,in_port_temp)
            # p.append((sw1,6,3))
            # p.append((sw3,1,2))
            # p.append((sw5,2,1))
            # p.append((sw7,3,6))
            self.mark=False
            sw1="00-00-00-00-00-01"
            sw2="00-00-00-00-00-02"
            sw3="00-00-00-00-00-03"
            eth_src3="00:00:00:00:00:03"
            eth_src4="00:00:00:00:00:04"
            _sw=[sw1,sw2,sw3]
            for temp_sw in _sw:
                ID=int(temp_sw[-1:])
                if ID==1:
                    in_port_temp=5
                    self.delete_old_flow(temp_sw,eth_src3,in_port_temp)
                elif ID==2:
                    in_port_temp=2
                    self.delete_old_flow(temp_sw,eth_src3,in_port_temp)
            for temp_sw in _sw:
                ID=int(temp_sw[-1:])
                if ID==1:
                    in_port_temp=3
                    self.delete_old_flow(temp_sw,eth_src4,in_port_temp)
                elif ID==2:
                    in_port_temp=4
                    self.delete_old_flow(temp_sw,eth_src4,in_port_temp)
            p.append((sw1,5,2))
            p.append((sw3,1,2))
            p.append((sw2,1,4))

            self._install_optimization_path(p,ev)
            p = [(sw, out_port, in_port) for sw, in_port, out_port in p]
            self._install_optimization_path(p,ev)

    def delete_old_flow(self, sw,src,in_port_temp):
        ID=int(sw[-1:])
        datapath=self.datapath_list[ID]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port_temp,eth_src=src)
        mod = parser.OFPFlowMod(
            datapath, command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,out_group=ofproto.OFPG_ANY,
            priority=1, match=match)
        datapath.send_msg(mod)


    def arp_handler(self, header_list, datapath, in_port, msg_buffer_id):
        header_list = header_list
        datapath = datapath
        in_port = in_port

        if ETHERNET in header_list:
            eth_dst = header_list[ETHERNET].dst
            eth_src = header_list[ETHERNET].src

        if eth_dst == ETHERNET_MULTICAST and ARP in header_list:
            arp_dst_ip = header_list[ARP].dst_ip
            if (datapath.id, eth_src, arp_dst_ip) in self.sw:  # Break the loop
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
                if arp_dst_ip in self.arp_table:  # arp reply
                    actions.append(datapath.ofproto_parser.OFPActionOutput(
                        in_port)
                    )

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

    def install_path(self,src_sw, dst_sw, in_port, last_port, ev):
        """
        Attempts to install a path between this switch and some destination
        """
        p = _get_path(src_sw, dst_sw, in_port, last_port)
        # if p is None:
        #   log.warning("Can't get from %s to %s", match.dl_src, match.dl_dst)
        #
        #   import pox.lib.packet as pkt
        #
        #   if (match.dl_type == pkt.ethernet.IP_TYPE and
        #       event.parsed.find('ipv4')):
        #     # It's IP -- let's send a destination unreachable
        #     log.debug("Dest unreachable (%s -> %s)",
        #               match.dl_src, match.dl_dst)
        #
        #     from pox.lib.addresses import EthAddr
        #     e = pkt.ethernet()
        #     e.src = EthAddr(dpid_to_str(self.dpid)) #FIXME: Hmm...
        #     e.dst = match.dl_src
        #     e.type = e.IP_TYPE
        #     ipp = pkt.ipv4()
        #     ipp.protocol = ipp.ICMP_PROTOCOL
        #     ipp.srcip = match.nw_dst #FIXME: Ridiculous
        #     ipp.dstip = match.nw_src
        #     icmp = pkt.icmp()
        #     icmp.type = pkt.ICMP.TYPE_DEST_UNREACH
        #     icmp.code = pkt.ICMP.CODE_UNREACH_HOST
        #     orig_ip = event.parsed.find('ipv4')
        #
        #     d = orig_ip.pack()
        #     d = d[:orig_ip.hl * 4 + 8]
        #     import struct
        #     d = struct.pack("!HH", 0,0) + d #FIXME: MTU
        #     icmp.payload = d
        #     ipp.payload = icmp
        #     e.payload = ipp
        #     msg = of.ofp_packet_out()
        #     msg.actions.append(of.ofp_action_output(port = event.port))
        #     msg.data = e.pack()
        #     self.connection.send(msg)
        #
        #   return
        #print p
        #log.debug("Installing path for %s -> %s %04x (%i hops)",
        #match.dl_src, match.dl_dst, match.dl_type, len(p))

        # We have a path -- install it
        self._install_path(p, ev)

        # Now reverse it and install it backwards
        # (we'll just assume that will work)
        # p = [(sw, out_port, in_port) for sw, in_port, out_port in p]
        # self._install_path(p, ev)

    def _install_path(self, p, ev):
        #wp = WaitingPath(p, packet_in)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src= eth.src
        if p==None:
            return
        for sw, in_port, out_port in p:
            # self._install(sw, in_port, out_port, match)
            # msg = of.ofp_barrier_request()
            # sw.connection.send(msg)
            #wp.add_xid(sw.dpid,msg.xid)
            #match = parser.OFPMatch(in_port=in_port,eth_src=src)
            ID=int(sw[-1:])
            if ID==1 and src=="00:00:00:00:00:01" or ID==1 and src=="00:00:00:00:00:02":
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port,eth_src=src,ip_proto=17,eth_type=0x0800)
            elif ID==1 and src=="00:00:00:00:00:05" or ID==1 and src=="00:00:00:00:00:06":
                actions = [parser.OFPActionSetQueue(1),parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port,eth_src=src,ip_proto=17,eth_type=0x0800)
            else:
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port,eth_src=src)

            #actions = [parser.OFPActionOutput(out_port)]
            datapath=self.datapath_list[ID]
            self.add_flow(datapath, 1, match, actions)

    def _install_optimization_path(self, p, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # for sw, in_port, out_port in p:
        #     ID=int(sw[-1:])
        #     if ID==1 and in_port==6:
        #         src_ip='10.0.0.3'
        #         src_mac='00:00:00:00:00:03'
        #         #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
        #         match = parser.OFPMatch(in_port=in_port)
        #     elif ID==1 and in_port==3:
        #         src_ip='10.0.0.4'
        #         src_mac='00:00:00:00:00:04'
        #         #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
        #         match = parser.OFPMatch(in_port=in_port)
        #     elif ID==3 and in_port==1:
        #         src_ip='10.0.0.3'
        #         src_mac='00:00:00:00:00:03'
        #         #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
        #         match = parser.OFPMatch(in_port=in_port)
        #     elif ID==3 and in_port==2:
        #         src_ip='10.0.0.4'
        #         src_mac='00:00:00:00:00:04'
        #         #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
        #         match = parser.OFPMatch(in_port=in_port)
        #     elif ID==5 and in_port==2:
        #         src_ip='10.0.0.3'
        #         src_mac='00:00:00:00:00:03'
        #         #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
        #         match = parser.OFPMatch(in_port=in_port)
        #     elif ID==5 and in_port==1:
        #         src_ip='10.0.0.4'
        #         src_mac='00:00:00:00:00:04'
        #         #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
        #         match = parser.OFPMatch(in_port=in_port)
        #     elif ID==7 and in_port==3:
        #         src_ip='10.0.0.3'
        #         src_mac='00:00:00:00:00:03'
        #         #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
        #         match = parser.OFPMatch(in_port=in_port)
        #     elif ID==7 and in_port==6:
        #         src_ip='10.0.0.4'
        #         src_mac='00:00:00:00:00:04'
        #         #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
        #         match = parser.OFPMatch(in_port=in_port)

        for sw, in_port, out_port in p:
            ID=int(sw[-1:])
            if ID==1 and in_port==5:
                src_ip='10.0.0.3'
                src_mac='00:00:00:00:00:03'
                #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
                match = parser.OFPMatch(in_port=in_port)
            elif ID==1 and in_port==2:
                src_ip='10.0.0.4'
                src_mac='00:00:00:00:00:04'
                #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
                match = parser.OFPMatch(in_port=in_port)
            elif ID==3 and in_port==1:
                src_ip='10.0.0.3'
                src_mac='00:00:00:00:00:03'
                #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
                match = parser.OFPMatch(in_port=in_port)
            elif ID==3 and in_port==1:
                src_ip='10.0.0.4'
                src_mac='00:00:00:00:00:04'
                #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
                match = parser.OFPMatch(in_port=in_port)
            elif ID==2 and in_port==1:
                src_ip='10.0.0.3'
                src_mac='00:00:00:00:00:03'
                #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
                match = parser.OFPMatch(in_port=in_port)
            elif ID==2 and in_port==4:
                src_ip='10.0.0.4'
                src_mac='00:00:00:00:00:04'
                #match = parser.OFPMatch(in_port=in_port,eth_src=src_mac,ipv4_src=src_ip,eth_type=0x0800,ip_proto=1)
                match = parser.OFPMatch(in_port=in_port)
            actions = [parser.OFPActionOutput(out_port)]
            datapath=self.datapath_list[ID]
            self.add_flow(datapath, 65535, match, actions)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        global sws
        sws = ['00-00-00-00-00-0' + str(switch.dp.id) for switch in switch_list]
        sw_Num = [switch.dp.id for switch in switch_list]
        # print 'switch_lists: %s' % sws
        # for switch in switch_list:
        #     print switch
        links_list = get_link(self.topology_api_app, None)
        # for link_i in links_list:
        #     print 'links_list: %s' % link_i
        #links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        for link in links_list:
            sw_src = '00-00-00-00-00-0' + str(link.src.dpid)
            sw_dst = '00-00-00-00-00-0' + str(link.dst.dpid)
            adjacency[sw_src][sw_dst] = link.src.port_no

        global delay
        global cost
        delay = [[0 for x in range(len(sw_Num))] for y in range(len(sw_Num))]
        cost = [[0 for x in range(len(sw_Num))] for y in range(len(sw_Num))]

    # def update_dist(self,v_num,d,lamb):
    #     tmp_index=S[len(S)-1]['index']
    #     tmp_val=S[len(S)-1]['val']
    #     i=0
    #     while(i<v_num):
    #         if(self.v_in_S(i+1)=="NO"):
    #             i_dist=tmp_val+edge[tmp_index-1][i]
    #             if(dist[i]>i_dist):
    #                 dist[i]=i_dist
    #                 pre[i+1]=tmp_index
    #         i=i+1
    #
    #     while(i<v_num):
    #         if (self.v_in_S(i+1)=="NO"):
    #             #random discretization
    #             tem=[math.ceil(delay[tmp_index-1][i]*lamb/r),math.floor(delay[tmp_index-1][i]*lamb/r)]
    #             dis_delay[tmp_index-1][i]=random.choice(tem)
    #             lin_error[tmp_index-1][i]=delay[tmp_index-1][i]-dis_delay[tmp_index-1][i]*r/lamb
    #
    #             D=d+dis_delay[tmp_index-1][i]
    #             error=dis_error[tmp_index,d]+lin_error[tmp_index-1][i]
    #             if error<0:
    #                 error=error+r/lamb
    #                 D=d-1
    #             if D<=lamb and weight[i+1,D]>weight[tmp_index,d]+cost[tmp_index-1][i]:
    #                 weight[i+1,D]=weight[tmp_index,d]+cost[tmp_index-1][i]
    #                 last_link[i+1,D]=tmp_index
    #                 if error<dis_error[i+1,D]:
    #                     dis_error[i+1,D]=error
    #
    # def v_in_S(self,v):
    #     i=0
    #     while(i<len(S)):
    #         if(v==S[i]['index']):
    #             return "YES"
    #         i=i+1
    #     return "NO"
    #
    # def get_min(self):
    #     if(len(dist)<1):
    #         return {'index':-1,'val':0}
    #     i=0
    #     min_val=MAX_NUM
    #     min_index=0
    #     while(i<len(dist)):
    #         if(self.v_in_S(i+1)=="NO"):
    #             if(dist[i] < MAX_NUM and dist[i] > 0 and min_val>dist[i]):
    #                 min_val=dist[i]
    #                 min_index=i
    #         i=i+1
    #     return {'index':min_index+1,'val':min_val}
    #
    # def process(self,sw_set,d,lamb):
    #     i=0
    #     S_len=len(S)
    #     v_num=len(sw_set)
    #     while(v_num != S_len and i<v_num):
    #         min_vertex=self.get_min()
    #         if(min_vertex['index']>0):
    #             S.append(min_vertex)
    #             self.update_dist(v_num,d,lamb)
    #         i=i+1
    #         S_len=len(S)
    #
    # def Initialize(self,sw_Num,s,lamb):
    #     for v in sw_Num:
    #         for i in range(0,lamb+1):
    #             weight[v,i]=10000 #the cost of the cheapest path p
    #             last_link[v,i]=None #the last link of the path
    #             dis_error[v,i]=10000 #keep the minimum discretization error
    #     weight[s,0]=0
    #     for i in range(0,lamb+1):
    #         dis_error[s,i]=0
    #
    #     S.append({'index':s,'val':0})
    #     a=0
    #     min_dist=10000
    #     v_num=len(sw_Num)
    #     while(a<v_num):
    #         dist.append(edge[s-1][a])
    #         #find Precursor node of start
    #         if edge[s-1][a]!=0 and min_dist>edge[s-1][a]:
    #             min_dist=edge[s-1][a]
    #             pre[a+1]=s
    #         a=a+1
    #
    # def RDA_Dijkstra(self,src,lamb):
    #     self.Initialize(sw_Num,src,lamb)
    #     for i in range(0,lamb+1):
    #         self.process(sw_Num,i,lamb)
    #
    # def RDA(self,src,dst):
    #     lamb=1
    #     path_delay=1000
    #     x=0.5
    #     while path_delay>(1+x)*r:
    #         lamb =2*lamb
    #         self.RDA_Dijkstra(src,lamb)
    #         path_delay=last_link[dst]

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)
        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])
