my_dissector_folder_path = my_dissector_folder_path or "/Applications/ZeroBraneStudio.app/Contents/ZeroBraneStudio/WireBait/example/"
print("LOADING EVERYTHING in '" .. my_dissector_folder_path .. "'")

local p = my_dissector_folder_path;

package.path = package.path .. ";" .. p .. "../../?.lua"

dofile(p .. "simple_dissector2.lua")


local wireshark = require("wirebait.wireshark_api_mock")
local wirebait = require("wirebait.wirebait")
base = wireshark.base;
ProtoField = wireshark.ProtoField;
Proto = wireshark.Proto.new;

buffer = wireshark.buffer.new(string.gsub("04 00 00 00 00 00 00 00 02 10 00 00 6d 61 72 6b 75 73 2e 6c 65 62 61 6c 6c 65 75 78", "%s+", ""));
tree = wireshark.treeitem.new();
pinfo = nil;
 

local dissector = wirebait.dissector.new();
dissector.registerField("uint64", "Sequence Number", "smp.SequenceNumber")


local dissectionFunction = function (buffer, pinfo, tree) 
  --packet_header_tree = tree:add("smp.packetHeader", "Packet Header", 8);
  --_,seq_no = packet_header_tree:add(f_SequenceNumber);
  --TODO: work on this
end

dissector.setDissectionFunction(dissectionFunction);

local p_smp = dissector.generateDissector("Simple Protocol", "smp");

p_smp.dissector(buffer, tree, pinfo);

print("haha!");