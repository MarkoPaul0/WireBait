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


--[[ Demo protocol contains all the wireshark datatypes currently supported by Wirebait
    so as to showcase Wirebait's capabilities.
    --]]--

--[[Use this snipet of code to test your dissector. You can test your dissector without wireshark by running the dissector script directly!]]
if disable_lua == nil and not _WIREBAIT_ON_ then  --disable_lua == nil checks if this script is being run from wireshark.
  local wirebait = require("wirebaitlib");
  local dissector_tester = wirebait.new({dissector_filepath="example/demo_dissector.lua", only_show_dissected_packets=true});
  local demo_dissector_hex_data = "0E 07 DE 02 22 FC 03 19   75 5A 7F FF FF FF FF FF"
  .. "FF FF F2 F8 22 FD DD 04  FC E6 8A A6 80 00 00 00  00 00 00 01 57 69 72 65  62 61 69 74 00 62 79 20" 
  .. "4D 61 72 6B 6F 50 61 75  6C 30 00 00 AA BB CC 11  22 33 C0 A8 0E 1C AB CD  EF 12 34 56 78 90 AB CD" 
  .. "EF 12 34 56 78 90 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00" 
  .. "00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00" 
  .. "00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00";
  --[[Note that the white spaces don't matter in the hex string.]]
  
  --[[Two options here:
        - call dissector_tester:dissectHexData() to dissect hex data from a string (no pcap needed) 
        - call dissector_tester:dissectPcap() to dissect packets from a pcap file]]
  dissector_tester:dissectHexData(demo_dissector_hex_data)    --dissection from hex data contained in a string
  return
end
----------------------------------------------------------------------------------------------------------------------------------------------


local p_demo    = Proto("demo1", "Demo Protocol1");
local f_bool    = ProtoField.bool("demo.bool", "Boolean");
local f_uint8   = ProtoField.uint8("demo.uint8", "8-bit uint");
local f_uint16  = ProtoField.uint16("demo.uint16", "16-bit uint");
local f_uint24  = ProtoField.uint24("demo.uint24", "24-bit uint");
local f_uint32  = ProtoField.uint32("demo.uint32", "32-bit uint");
local f_uint64  = ProtoField.uint64("demo.uint64", "64-bit uint");
local f_int8    = ProtoField.int8("demo.int8", "8-bit int");
local f_int16   = ProtoField.int16("demo.int16", "16-bit int");
local f_int24   = ProtoField.int24("demo.int24", "24-bit int");
local f_int32   = ProtoField.int32("demo.int32", "32-bit int");
local f_int64   = ProtoField.int64("demo.int64", "64-bit int");
local f_float   = ProtoField.float("demo.float", "Float");
local f_double  = ProtoField.double("demo.double", "Double");
local f_string  = ProtoField.string("demo.string", "String");
local f_stringz = ProtoField.stringz("demo.stringz", "Stringz");
local f_ether   = ProtoField.ether("demo.ether", "ethernet");
local f_bytes   = ProtoField.bytes("demo.bytes", "bytes");
local f_ipv4    = ProtoField.ipv4("demo.ipv4", "IPv4");
local f_guid    = ProtoField.guid("demo.guid", "GUID");

p_demo.fields = {f_bool, 
  f_uint8, f_uint16, f_uint24, f_uint32, f_uint64, 
  f_int8, f_int16, f_int24, f_int32, f_int64, 
  f_float, f_double, 
  f_string, f_stringz, 
  f_ether, f_bytes, f_ipv4, f_guid,};

function p_demo.dissector(buffer, packet_info, root_tree)
  packet_info.cols.protocol = "Demo";
  main_tree = root_tree:add(p_demo, buffer(0,86))
  
  uints_tree = main_tree:add(buffer(0,18), "Unsigned integers:");
  uints_tree:add(f_uint8, buffer(0,1));
  uints_tree:add(f_uint16, buffer(1,2));
  uints_tree:add(f_uint24, buffer(3,3));
  uints_tree:add(f_uint32, buffer(6,4));
  uints_tree:add(f_uint64, buffer(10,8));
  ints_tree = main_tree:add(buffer(18,18), "Signed integers:");
  ints_tree:add(f_int8, buffer(18,1));
  ints_tree:add(f_int16, buffer(19,2));
  ints_tree:add(f_int24, buffer(21,3));
  ints_tree:add(f_int32, buffer(24,4));
  ints_tree:add(f_int64, buffer(28,8));
  strings_tree = main_tree:add(buffer(36,24), "Strings:");
  strings_tree:add(f_string, buffer(36,24));
  strings_tree:add(f_stringz, buffer(36,24));
  others_tree = main_tree:add(buffer(60,26), "Other types:");
  others_tree:add(f_bytes, buffer(60,26));
  others_tree:add(f_ether, buffer(60,6));
  others_tree:add(f_ipv4, buffer(66,4));
  others_tree:add(f_guid, buffer(70,16));
end

local udp_encap_table = DissectorTable.get("udp.port")
--udp_encap_table:add(59121, p_demo)
udp_encap_table:add(7437, p_demo)
