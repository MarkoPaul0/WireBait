my_dissector_folder_path = my_dissector_folder_path or "C:/Users/Marko/Documents/GitHub/wirebait/example/"
print("LOADING EVERYTHING in '" .. my_dissector_folder_path .. "'")

local p = my_dissector_folder_path;

package.path = package.path .. ";" .. p .. "../../?.lua"

dofile(p .. "simple_dissector2.lua")


local wireshark = require("wirebait.wireshark_api_mock")
local wirebait = require("wirebait.wirebait")
base = wireshark.base;
Protofield = wireshark.Protofield;

buffer = wireshark.buffer.new("AABBCCBBEEFF");
tree = wireshark.treeitem.new();
pinfo = nil;

dissectionFunction(buffer, pinfo, tree)

print("haha!");