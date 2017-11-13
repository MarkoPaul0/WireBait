my_dissector_folder_path = my_dissector_folder_path or "/Users/marko/Desktop/Projects/Lua/wirebait/example/"
print("LOADING EVERYTHING in '" .. my_dissector_folder_path .. "'")

local p = my_dissector_folder_path;

package.path = package.path .. ";" .. p .. "../../?.lua"

dofile(p .. "simple_dissector2.lua")


local wireshark = require("wirebait.wireshark_api_mock")
local wirebait = require("wirebait.wirebait")
base = wireshark.base;
Protofield = wireshark.Protofield;

buffer = wireshark.buffer.new(string.gsub("04 00 00 00 00 00 00 00 02 10 00 00 6d 61 72 6b 75 73 2e 6c 65 62 61 6c 6c 65 75 78", "%s+", ""));
tree = wireshark.treeitem.new();
pinfo = nil;

dissectionFunction(buffer, pinfo, tree)

print("haha!");