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
import logging

EXAMPLE="/root/AAAAA.txt"
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
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # inst = [parser.OFPInstructionMeter(1),
        # parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
        # actions)]
        bands = [#parser.OFPMeterBandDrop(rate=10000, burst_size=10)
                 parser.OFPMeterBandDscpRemark(rate=1000, burst_size=10,
                                               prec_level=1)]
        meter_mod = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD,
                                       flags=ofproto.OFPMF_KBPS, meter_id=1, bands=bands)
        datapath.send_msg(meter_mod)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                hard_timeout=15,
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
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        # if src not in self.mac_to_port[dpid]:
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        # Classify by port_no
        # if in_port==1:
        # actions = [parser.OFPActionOutput(out_port)
        #                                     ,parser.OFPActionSetQueue(1)]
        #     #actions = [parser.OFPActionOutput(out_port)]
        # elif in_port==2:
        #     actions = [parser.OFPActionOutput(out_port)#,parser.OFPActionSetField(ip_dscp=2)
        #                                     ,parser.OFPActionSetQueue(7)]
        # else:
        #     actions = [parser.OFPActionOutput(out_port)]
        #self.add_group_table(datapath)
        actions = [parser.OFPActionOutput(out_port),parser.OFPActionSetField(ip_dscp=18)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if dpid!=2:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst,eth_type=0x0800)
                self.add_flow(datapath, 1, match, actions)
            else:
                actions= [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst,ip_proto=17,eth_type=0x0800)
                self.modify_meter(datapath, match,actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        datapath.send_msg(out)
        #***self.send_flow_stats_request(datapath)
        #***self.sen_aggregate_stats_request(datapath)
        #***self.send_table_stats_request(datapath)
        #***self.send_port_stats_request(datapath)
        #***self.send_port_desc_stats_request(datapath)
        #***self.send_queue_stats_request(datapath)
        #***self.send_queue_get_config_request(datapath)
        #***self.send_group_stats_request(datapath)
        #***self.send_meter_stats_request(datapath)
        #***self.send_meter_config_stats_request(datapath)
        #***self.send_meter_features_stats_request(datapath)

    # ADD meter
    def add_flow_1(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionMeter(meter_id=1),
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
        # actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                #hard_timeout=20,
                                match=match, instructions=inst)

        datapath.send_msg(mod)
    #modify_meter
    def modify_meter(self, datapath, match,actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionMeter(meter_id=1),
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_ADD,
                                #hard_timeout=21,
                                match=match, instructions=inst)

        datapath.send_msg(mod)

    # individual flow statistics
    def send_flow_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch(in_port=1)
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                             ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY,
                                             cookie, cookie_mask, match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flow = []
        for stat in ev.msg.body:
            flow.append('table_id=%s' 'duration_sec=%d duration_nsec=%d'
                        'priority=%d'
                        'idle_timeout=%d hard_timeout=%d flags=0x%04x'
                        'cookie=%d pakect_count=%d byte_count=%d'
                        'match=%s instructions=%s' %
                        (stat.table_id,
                         stat.duration_sec, stat.duration_nsec,
                         stat.priority,
                         stat.idle_timeout, stat.hard_timeout, stat.flags,
                         stat.cookie, stat.packet_count, stat.byte_count,
                         stat.match, stat.instructions))

            logging.basicConfig(filename="ABC.txt",level=logging.WARNING)
            logging.info('FlowStats: %s', flow)
            #self.logger.info('FlowStats: %s', flow)

    # Aggregate flow statistics
    def sen_aggregate_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch(in_port=1)
        req = ofp_parser.OFPAggregateStatsRequest(datapath, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY,
                                                  ofp.OFPG_ANY, cookie, cookie_mask, match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
    def aggregate_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('AggregateStats: packet_count=%d byte_count=%d' 'flow_count=%d',
                         body.packet_count, body.byte_count, body.flow_count)

    # Table statistics
    def send_table_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPTableStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
    def table_stats_reply_handler(self, ev):
        tables = []
        for stat in ev.msg.body:
            tables.append('table_id=%d active_count=%d lookup_count=%d '
                          ' matched_count=%d' %
                          (stat.table_id, stat.active_count,
                           stat.lookup_count, stat.matched_count))
        self.logger.info('TableStats: %s', tables)

    #port statistic
    def send_port_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        ports = []
        for stat in ev.msg.body:
            ports.append('port_no=%d ' 'rx_packets=%d tx_packets=%d '
                         'rx_bytes=%d tx_bytes=%d ''rx_dropped=%d tx_dropped=%d '
                         'rx_errors=%d tx_errors=%d '
                         'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
                         'collisions=%d duration_sec=%d duration_nsec=%d' %
                         (stat.port_no,
                          stat.rx_packets, stat.tx_packets,
                          stat.rx_bytes, stat.tx_bytes,
                          stat.rx_dropped, stat.tx_dropped,
                          stat.rx_errors, stat.tx_errors,
                          stat.rx_frame_err, stat.rx_over_err,
                          stat.rx_crc_err, stat.collisions,
                          stat.duration_sec, stat.duration_nsec))
        self.logger.info('PortStats: %s', ports)

    #port description
    def send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        ports = []
        for p in ev.msg.body:
            ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                         'state=0x%08x curr=0x%08x advertised=0x%08x '
                         'supported=0x%08x peer=0x%08x curr_speed=%d '
                         'max_speed=%d' %
                         (p.port_no, p.hw_addr,
                          p.name, p.config,
                          p.state, p.curr, p.advertised,
                          p.supported, p.peer, p.curr_speed,
                          p.max_speed))
        self.logger.info('OFPPortDescStatsReply received: %s', ports)

    #queue statistics
    def send_queue_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPQueueStatsRequest(datapath, 0, ofp.OFPP_ANY,
                                              ofp.OFPQ_ALL)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPQueueStatsReply, MAIN_DISPATCHER)
    def queue_stats_reply_handler(self, ev):
        queues = []
        for stat in ev.msg.body:
            queues.append('port_no=%d queue_id=%d '
                          'tx_bytes=%d tx_packets=%d tx_errors=%d '
                          'duration_sec=%d duration_nsec=%d' %
                          (stat.port_no, stat.queue_id,
                           stat.tx_bytes, stat.tx_packets, stat.tx_errors,
                           stat.duration_sec, stat.duration_nsec))
        self.logger.info('QueueStats: %s', queues)

    #queue configuration message
    def send_queue_get_config_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPQueueGetConfigRequest(datapath, ofp.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPQueueGetConfigReply, MAIN_DISPATCHER)
    def queue_get_config_reply_handler(self, ev):
        msg = ev.msg
        self.logger.info('OFPQueueGetConfigReply received: '
                         'port=%s queues=%s',
                         msg.port, msg.queues)

    #group statistics
    def send_group_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPGroupStatsRequest(datapath, 0, ofp.OFPG_ALL)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPGroupStatsReply, MAIN_DISPATCHER)
    def group_stats_reply_handler(self, ev):
        groups = []
        for stat in ev.msg.body:
            groups.append('length=%d group_id=%d '
                          'ref_count=%d packet_count=%d byte_count=%d '
                          'duration_sec=%d duration_nsec=%d' %
                          (stat.length, stat.group_id,
                           stat.ref_count, stat.packet_count,
                           stat.byte_count, stat.duration_sec,
                           stat.duration_nsec))
        self.logger.info('GroupStats: %s', groups)

    #meter statistics
    def send_meter_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPMeterStatsRequest(datapath, 0, ofp.OFPM_ALL)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_reply_handler(self, ev):
        meters = []
        for stat in ev.msg.body:
            meters.append('meter_id=0x%08x len=%d flow_count=%d '
                          'packet_in_count=%d byte_in_count=%d '
                          'duration_sec=%d duration_nsec=%d '
                          'band_stats=%s' %
                          (stat.meter_id, stat.len, stat.flow_count,
                           stat.packet_in_count, stat.byte_in_count,
                           stat.duration_sec, stat.duration_nsec,
                           stat.band_stats))
        self.logger.info('MeterStats: %s', meters)

    #meter configuration statistics
    def send_meter_config_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPMeterConfigStatsRequest(datapath, 0, ofp.OFPM_ALL)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPMeterConfigStatsReply, MAIN_DISPATCHER)
    def meter_config_stats_reply_handler(self, ev):
        configs = []
        for stat in ev.msg.body:
            configs.append('length=%d flags=0x%04x meter_id=0x%08x '
                           'bands=%s' %
                           (stat.length, stat.flags, stat.meter_id,
                            stat.bands))
        self.logger.info('MeterConfigStats: %s', configs)

    #meter feature statistics    
    def send_meter_features_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPMeterFeaturesStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPMeterFeaturesStatsReply, MAIN_DISPATCHER)
    def meter_features_stats_reply_handler(self, ev):
        features = []
        for stat in ev.msg.body:
            features.append('max_meter=%d band_types=0x%08x '
                            'capabilities=0x%08x max_bands=%d '
                            'max_color=%d' %
                            (stat.max_meter, stat.band_types,
                             stat.capabilities, stat.max_bands,
                             stat.max_color))
        self.logger.info('MeterFeaturesStats: %s', features)

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
        
    