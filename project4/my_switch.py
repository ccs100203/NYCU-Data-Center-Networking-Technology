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
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from array import array

# project4
SWITCH_NUM = 15
HOST_NUM = 16
# MAC to vlan
mac_vlan_mapping = {}
# check if a edge switch
is_edge = [False] * (SWITCH_NUM+1)
# port to MAC on each edge switch
port_mac = [[0 for x in range(4)] for y in range(SWITCH_NUM+1)]

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # project4
        for i in range(HOST_NUM):
            mac_vlan_mapping['00:00:00:00:00:' + hex(i+1).split('x')[-1].zfill(2)] = (i % 3) + 1
        for k in mac_vlan_mapping:
            print(k, mac_vlan_mapping[k])

        is_edge[4] = True
        is_edge[5] = True
        is_edge[7] = True
        is_edge[8] = True
        is_edge[11] = True
        is_edge[12] = True
        is_edge[14] = True
        is_edge[15] = True

        port_mac[4][1] = '00:00:00:00:00:01'
        port_mac[4][2] = '00:00:00:00:00:02'
        port_mac[5][1] = '00:00:00:00:00:03'
        port_mac[5][2] = '00:00:00:00:00:04'
        port_mac[7][1] = '00:00:00:00:00:05'
        port_mac[7][2] = '00:00:00:00:00:06'
        port_mac[8][1] = '00:00:00:00:00:07'
        port_mac[8][2] = '00:00:00:00:00:08'
        port_mac[11][1] = '00:00:00:00:00:09'
        port_mac[11][2] = '00:00:00:00:00:0a'
        port_mac[12][1] = '00:00:00:00:00:0b'
        port_mac[12][2] = '00:00:00:00:00:0c'
        port_mac[14][1] = '00:00:00:00:00:0d'
        port_mac[14][2] = '00:00:00:00:00:0e'
        port_mac[15][1] = '00:00:00:00:00:0f'
        port_mac[15][2] = '00:00:00:00:00:10'

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
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
            
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if dst in mac_vlan_mapping or dst.find('ff:ff:ff') != -1:
        #     self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        
        # if true, then add rule into switch
        is_edge_in_table = False

        # filter different tenant
        if is_edge[int(dpid)] and dst in mac_vlan_mapping and mac_vlan_mapping[src] != mac_vlan_mapping[dst]:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            print('diff tenant')
            return

        # deal with flood packet in edge switches
        if is_edge[int(dpid)] and dst.find('ff:ff:ff') != -1:
            actions = []
            # send to the below host
            if src != port_mac[int(dpid)][1] and src != port_mac[int(dpid)][2]:
                print('send to host')
                vlan = mac_vlan_mapping[src]
                if mac_vlan_mapping[port_mac[int(dpid)][1]] == vlan:
                    out_port = 1
                elif mac_vlan_mapping[port_mac[int(dpid)][2]] == vlan:
                    out_port = 2
                else:
                    return
            # send to the above switch
            else:
                print('send to switch')
                out_port = 3
            actions.append(parser.OFPActionOutput(out_port))
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            return

        actions = []

        # lookup table
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            is_edge_in_table = True
            print('in table')
        else:
            # check whether has the same vlan in edge switch
            if dst in mac_vlan_mapping and is_edge[int(dpid)]:
                vlan = mac_vlan_mapping[dst]
                # print('vlan:', vlan)
                if mac_vlan_mapping[port_mac[int(dpid)][1]] == vlan:
                    # print('vlan2:', mac_vlan_mapping[port_mac[int(dpid)][1]])
                    out_port = 1
                    actions.append(parser.OFPActionOutput(out_port))
                elif mac_vlan_mapping[port_mac[int(dpid)][2]] == vlan:
                    # print('vlan3:', mac_vlan_mapping[port_mac[int(dpid)][2]])
                    out_port = 2
                    actions.append(parser.OFPActionOutput(out_port))

                out_port = 3
            # flood in core switches
            else:
                out_port = ofproto.OFPP_FLOOD

        actions.append(parser.OFPActionOutput(out_port))

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD and is_edge_in_table:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
