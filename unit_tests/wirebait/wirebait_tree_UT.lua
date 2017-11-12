
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

local is_standalone_test = not tester; --if only this file is being tested (not part of run all)

local function createTests() --keeping everything in a local scope to prevent interferences if multiple unit test files are run
    local wireshark = require("wirebait.wireshark_api_mock")
    local wirebait = require("wirebait.wirebait")
    tester = tester or require("wirebait.unit_tests.tester")

    base = wireshark.base --make available base as a global variable
    Protofield = wireshark.Protofield; --make available Protofield globally

    --Creating the unit tests
    unit_tests = tester.newUnitTestsSet("Wirebait Tree Unit Tests");

    unit_tests:addTest("Testing wirebait root tree construction", function()
            ws_tree = wireshark.treeitem.new();
            packet = string.gsub("6d 61 72 6b 75 73 2e 6c 65 62 61 6c 6c 65 75 78 00 00 00 00 00 00 00 00 00 00 00 00", "%s+", "") --gsub to remove whitespaces
            buffer = wireshark.buffer.new(packet);
            wb_tree = wirebait.tree.new(ws_tree, buffer, 2, 26);
            tester.assert(wb_tree.__buffer():len(), 28, "Wrong length!");
            tester.assert(wb_tree:position(), 2, "Wrong position!");
        end)

    unit_tests:addTest("Testing wirebait root tree construction with buffer too small", function()
            ws_tree = wireshark.treeitem.new();
            packet = string.gsub("6d 61 72 6b 75 73 2e 6c 65 62 61 6c 6c 65 75 78 00 00 00 00 00 00 00 00 00 00 00 00", "%s+", "") --gsub to remove whitespaces
            buffer = wireshark.buffer.new(packet); 
            success,error_msg = pcall(wirebait.tree.new, ws_tree, buffer, 4, 25);
            tester.assert(success, false, "This call should fail!")
        end)

    unit_tests:addTest("Testing wirebait tree:skip()", function()
            ws_tree = wireshark.treeitem.new();
            packet = string.gsub("6d 61 72 6b 75 73 2e 6c 65 62 61 6c 6c 65 75 78 00 00 00 00 00 00 00 00 00 00 00 00", "%s+", "") -- gsub to remove whitespaces
            buffer = wireshark.buffer.new(packet);
            wb_tree = wirebait.tree.new(ws_tree, buffer, 0);
            wb_tree:skip(3);
            tester.assert(wb_tree:position(), 3, "Wrong position!");
        end)

    unit_tests:addTest("Testing wirebait tree:skip() more bytes than managed", function()
            ws_tree = wireshark.treeitem.new();
            buffer = wireshark.buffer.new("A12B01");
            wb_tree = wirebait.tree.new(ws_tree, buffer, 0, 3);
            success,error_msg = pcall(wb_tree.skip, wb_tree, 4);
            tester.assert(success, false, "This call should fail!")
        end)

    unit_tests:addTest("Testing wirebait tree:add()", function()
            ws_tree = wireshark.treeitem.new();
            packet = string.gsub("74 68 69 73 2e 69 73 2e 57 69 72 65 62 61 69 74 2e 66 6f 72 2e 57 69 72 65 73 68 61 72 6b", "%s+", "")
            buffer = wireshark.buffer.new(packet);
            parent_tree = wirebait.tree.new(ws_tree, buffer, 0, 30);
            child_tree,value = parent_tree:addString("smp.someField", "Some Field", 16);
            tester.assert(parent_tree:position(), 16, "After adding a child, the parent's position should be moved by the child's size!");
            child_tree2,value2 = wb_tree:addString("smp.someField2", "Some Field2", 14);
            tester.assert(value, "this.is.Wirebait", "Wrong value was decoded!");
            tester.assert(value2, ".for.Wireshark", "Wrong value2 was decoded!");
        end)

    return unit_tests;
end

local unit_tests = createTests();
if is_standalone_test then
    tester.test(unit_tests);
    tester.printReport();
else
    return unit_tests
end

