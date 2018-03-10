
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

--local wireshark = require("wirebait.wireshark_api_mock")
--local wirebait = require("wirebait.wirebait")


--[[ Simple protocol "smp" with header containing sequence number + payload containing N messages
    header :
        - uint64 sequence_number
    payload : 
        message_header:
            - uint8 message_type
            - uint16 message_size
            - uint8 is_urgent 1 = true, 0 = false
            - char[24] username
        message_payload:
            <depending on message type>
--]]--


local p_smp = Proto.new("smp", "Simple Protocol");
local f_text = ProtoField.string("smp.string", "Some Header");
local f_uin32t = ProtoField.uint32("smp.int", "Some Integer");
local f_uin64t = ProtoField.uint64("smp.int64", "Some 64 bit int");
p_smp.fields = { f_text, f_uin32t };

function p_smp.dissector(buffer, packet_info, root_tree)
    --Dissecting packet header
    proto_tree = root_tree:add(p_smp, buffer(0,20))
    sub_tree = proto_tree:add(f_text, buffer(0,10));
    sub_tree:add(f_uin32t, buffer(2,4), 28, "hey: ", "hola");
    sub_tree:add(f_uin32t, buffer(4,6));
    sub_tree2 = proto_tree:add(f_uin64t, buffer(10,8));
end
