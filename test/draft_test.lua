
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


local wireshark = require("wirebait.test.wireshark_mock")
local wirebait = require("wirebait.wirebait")

base = wireshark.base --make available base as a global variable
Protofield = wireshark.Protofield; --make available Protofield globally

buffer = wireshark.buffer.new(128);

--local ws_test_tree = {
--        len = function ()
--            return 10;
--        end
--    }

--print(ws_test_tree:len())

ws_root_tree_item = wireshark.treeitem.new();
ws_child_tree_item = wireshark.treeitem.new();
ws_child_tree_item2 = wireshark.treeitem.new();
print("tr " .. tostring(ws_root_tree_item) .. " tr1 " .. tostring(ws_child_tree_item) .. " tr2 " .. tostring(ws_child_tree_item2) )

root_tree = wirebait.tree.new(ws_root_tree_item, buffer, 0);
print("root address " .. tostring(root_tree) .. " parent " .. tostring(root_tree:parent()))

--print("parent of root tree: " .. tostring(root_tree.parent()))

--print("old position " .. root_tree:position())
root_tree:skip(1)

--proto_field1  = wireshark.Protofield.new("proto_fied1", "test.pf1", {});
child_tree_1 = root_tree:addUint8("smp.child_tree1", "Child Tree 1");

--child_tree_1 = wirebait.tree.new(root_tree, proto_field1)
--print("child address " .. tostring(child_tree) .. "\n")

print("old position root: " .. root_tree:position() .. " child " .. child_tree_1:position())

--child_tree.parent();
child_tree_1:skip(3)
print("old position root: " .. root_tree:position() .. " child " .. child_tree_1:position())
--root_tree:skip(4)
print("old position root: " .. root_tree:position() .. " child " .. child_tree_1:position())
child_tree_1:skip(3)
print("old position root: " .. root_tree:position() .. " child " .. child_tree_1:position())
child_tree_1:autoFitHighlight(true)

print("Length for root_tree item is " .. tostring(root_tree:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(root_tree:wiresharkTree()));
print("Length for child_tree item is " .. tostring(child_tree_1:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_1:wiresharkTree()));


child_tree_2 = root_tree:addUint64("smp.child_tree2", "Child Tree 2");
--print("child address " .. tostring(child_tree) .. "\n")
--child_tree_2:skip(11);

print("old position root: " .. root_tree:position() .. " child2 " .. child_tree_2:position())
print("Length for root_tree item is " .. tostring(root_tree:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(root_tree:wiresharkTree()));
print("Length for child_tree item is " .. tostring(child_tree_1:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_1:wiresharkTree()));
print("Length for child_tree2 item is " .. tostring(child_tree_2:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_2:wiresharkTree()));
child_tree_2:autoFitHighlight(false)
print("Length for root_tree item is " .. tostring(root_tree:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(root_tree:wiresharkTree()));
print("Length for child_tree item is " .. tostring(child_tree_1:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_1:wiresharkTree()));
print("Length for child_tree2 item is " .. tostring(child_tree_2:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_2:wiresharkTree()));
child_tree_2:autoFitHighlight(true)
print("Length for root_tree item is " .. tostring(root_tree:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(root_tree:wiresharkTree()));
print("Length for child_tree item is " .. tostring(child_tree_1:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_1:wiresharkTree()));
print("Length for child_tree2 item is " .. tostring(child_tree_2:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_2:wiresharkTree()));