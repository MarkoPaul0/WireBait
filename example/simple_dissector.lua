
--[[
    WireBait for Wireshark is a lua package to help write Wireshark 
    Dissectors in lua
    Copyright (C) 2015-2017 Markus Leballeux

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
]]


--[[ Simple protocol "smp" with header containing sequence number + payload containing N messages
    header :
        - uint64 sequence_number
    payload : 
        message_header:
            - uint8 message_type
            - uint16 message_size
            - uint8 is_urgent 1 = true, 0 = false
            - char[24] username (null terminated)
        message_payload:
            <depending on message type>
--]]--

--[[Use this snipet of code to test your dissector. You can test your dissector without wireshark by running the dissector script directly!]]
if disable_lua == nil and not _WIREBAIT_ON_ then  --disable_lua == nil checks if this script is being run from wireshark.
  local wirebait = require("wirebait");
  local dissector_tester = wirebait.plugin_tester.new({only_show_dissected_packets=true});
  dissector_tester:dissectPcap("C:/Users/Marko/Desktop/wirebait_test2.pcap");
  return
end
----------------------------------------------------------------------------------------------------------------------------------------------


local p_smp = Proto("smp", "Simple Protocol");
local f_header = ProtoField.string("smp.Header", "Header"); --more of a place holder to organize the tree
local f_seq_no = ProtoField.uint64("smp.seq_no", "Sequence Number");
local f_type = ProtoField.uint8("smp.type", "Type");
local f_size = ProtoField.uint16("smp.size", "Size");
local f_is_urgent = ProtoField.uint8("smp.is_urgent", "Urgent");
local f_username = ProtoField.stringz("smp.", "Username");
local f_username2 = ProtoField.stringz("smp.", "Username");

p_smp.fields = {f_header, f_seq_no, f_type, f_size, f_is_urgent, f_username};

function p_smp.dissector(buffer, packet_info, root_tree)
  packet_info.cols.protocol = p_smp.name
  main_tree = root_tree:add(p_smp, buffer(0))
  
  hdr_tree = main_tree:add(f_header, buffer(0,28), "", "Header");
  hdr_tree:add(f_seq_no, buffer(0,8));
  hdr_tree:add(f_type, buffer(8,1));
  hdr_tree:add_le(f_size, buffer(9,2));
  hdr_tree:add(f_is_urgent, buffer(11,1));
  hdr_tree:append_text(" appendix :)")
  hdr_tree:add(f_username, buffer(12,24), buffer(12,24):stringz());
  hdr_tree:add(buffer(36,4), "Protofiel-less item");
end

local udp_encap_table = DissectorTable.get("udp.port")
--udp_encap_table:add(59121, p_smp)
udp_encap_table:add(7437, p_smp)
