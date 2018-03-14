--[[
    WireBait for Wireshark is a lua package to help write Wireshark 
    Dissectors in lua
    [Wirebait on Github](https://github.com/MarkoPaul0/WireBait)
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
local tester = tester or require("unit_tests.tester")
local wirebait = require("wirebait")

--[[ All variables here need to be kept local, however the unit test framework will run
each individual test function added with UnitTestsSet:addTest() in its own environment,
therefore forgetting the local keywork will not have a negative impact.
]]--
--Creating unit tests
local unit_tests = tester.newUnitTestsSet("Wireshark Protofield Unit Tests");

unit_tests:addTest("Testing wireshark protofield construction with new()", function()
        proto_field = wirebait.ProtoField.new("smp.someField", "Some Field", "uint16")
        tester.assert(proto_field.m_name, "Some Field", "Wrong name!")
        tester.assert(proto_field.m_abbr, "smp.someField", "Wrong filter!")
        tester.assert(proto_field.m_size, 2, "Wrong size!")
        tester.assert(proto_field.m_type, "uint16", "Wrong type!")
    end);

unit_tests:addTest("Testing wireshark protofield construction with uint8()", function()
        ws_protfield = wirebait.ProtoField.uint8("smp.someField", "Some Field")
        tester.assert(ws_protfield.m_name, "Some Field", "Wrong name!")
        tester.assert(ws_protfield.m_abbr, "smp.someField", "Wrong filter!")
        tester.assert(ws_protfield.m_size, 1, "Wrong size!")
        tester.assert(ws_protfield.m_type, "uint8", "Wrong type!")
    end);

unit_tests:addTest("Testing wireshark protofield construction with uint16()", function()
        ws_protfield = wirebait.ProtoField.uint16("smp.someField", "Some Field")
        tester.assert(ws_protfield.m_name, "Some Field", "Wrong name!")
        tester.assert(ws_protfield.m_abbr, "smp.someField", "Wrong filter!")
        tester.assert(ws_protfield.m_size, 2, "Wrong size!")
        tester.assert(ws_protfield.m_type, "uint16", "Wrong type!")
    end);

unit_tests:addTest("Testing wireshark protofield construction with uint32()", function()
        ws_protfield = wirebait.ProtoField.uint32("smp.someField", "Some Field")
        tester.assert(ws_protfield.m_name, "Some Field", "Wrong name!")
        tester.assert(ws_protfield.m_abbr, "smp.someField", "Wrong filter!")
        tester.assert(ws_protfield.m_size, 4, "Wrong size!")
        tester.assert(ws_protfield.m_type, "uint32", "Wrong type!")
    end);

unit_tests:addTest("Testing wireshark protofield construction with uint64()", function()
        ws_protfield = wirebait.ProtoField.uint64("smp.someField", "Some Field")
        tester.assert(ws_protfield.m_name, "Some Field", "Wrong name!")
        tester.assert(ws_protfield.m_abbr, "smp.someField", "Wrong filter!")
        tester.assert(ws_protfield.m_size, 8, "Wrong size!")
        tester.assert(ws_protfield.m_type, "uint64", "Wrong type!")
    end);

unit_tests:addTest("Testing wireshark protofield construction with string()", function()
        ws_protfield = wirebait.ProtoField.string("smp.someField", "Some Field")
        tester.assert(ws_protfield.m_name, "Some Field", "Wrong name!")
        tester.assert(ws_protfield.m_abbr, "smp.someField", "Wrong filter!")
        tester.assert(ws_protfield.m_size, nil, "Wrong size!")
        tester.assert(ws_protfield.m_type, "string", "Wrong type!")
    end);

--unit_tests:addTest("Testing wireshark protofield construction with string() without override size", function()
--        success,error_msg = pcall(wirebait.ProtoField.string, "smp.someField", "Some Field");
--        tester.assert(success, false, "This call should fail!")
--    end);

if is_standalone_test then
    tester.test(unit_tests);
    tester.printReport();
else
    return unit_tests
end

