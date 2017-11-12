
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
local tester = tester or require("wirebait.unit_tests.tester")

local function createTests() --keeping everything in a local scope to prevent interferences if multiple unit test files are run
    local wireshark = require("wirebait.wireshark_api_mock")

    --Creating unit tests
    local unit_tests = tester.newUnitTestsSet("Wireshark Protofield Unit Tests");

    unit_tests:addTest("Testing wireshark protofield construction with new()", function()
            ws_protfield = wireshark.Protofield.new("Some Field", "smp.someField", "uint16")
            tester.assert(ws_protfield.m_name, "Some Field", "Wrong name!")
            tester.assert(ws_protfield.m_abbr, "smp.someField", "Wrong filter!")
            tester.assert(ws_protfield.m_size, 2, "Wrong size!")
            tester.assert(ws_protfield.m_type, "uint16", "Wrong type!")
        end);
    
    unit_tests:addTest("Testing wireshark protofield construction with uint8()", function()
            ws_protfield = wireshark.Protofield.uint8("Some Field", "smp.someField")
            tester.assert(ws_protfield.m_name, "Some Field", "Wrong name!")
            tester.assert(ws_protfield.m_abbr, "smp.someField", "Wrong filter!")
            tester.assert(ws_protfield.m_size, 1, "Wrong size!")
            tester.assert(ws_protfield.m_type, "uint8", "Wrong type!")
        end);
    
    unit_tests:addTest("Testing wireshark protofield construction with uint16()", function()
            ws_protfield = wireshark.Protofield.uint16("Some Field", "smp.someField")
            tester.assert(ws_protfield.m_name, "Some Field", "Wrong name!")
            tester.assert(ws_protfield.m_abbr, "smp.someField", "Wrong filter!")
            tester.assert(ws_protfield.m_size, 2, "Wrong size!")
            tester.assert(ws_protfield.m_type, "uint16", "Wrong type!")
        end);
    
    unit_tests:addTest("Testing wireshark protofield construction with uint32()", function()
            ws_protfield = wireshark.Protofield.uint32("Some Field", "smp.someField")
            tester.assert(ws_protfield.m_name, "Some Field", "Wrong name!")
            tester.assert(ws_protfield.m_abbr, "smp.someField", "Wrong filter!")
            tester.assert(ws_protfield.m_size, 4, "Wrong size!")
            tester.assert(ws_protfield.m_type, "uint32", "Wrong type!")
        end);
    
    unit_tests:addTest("Testing wireshark protofield construction with uint64()", function()
            ws_protfield = wireshark.Protofield.uint64("Some Field", "smp.someField")
            tester.assert(ws_protfield.m_name, "Some Field", "Wrong name!")
            tester.assert(ws_protfield.m_abbr, "smp.someField", "Wrong filter!")
            tester.assert(ws_protfield.m_size, 8, "Wrong size!")
            tester.assert(ws_protfield.m_type, "uint64", "Wrong type!")
        end);
    
    unit_tests:addTest("Testing wireshark protofield construction with string()", function()
            ws_protfield = wireshark.Protofield.string("Some Field", "smp.someField", 42)
            tester.assert(ws_protfield.m_name, "Some Field", "Wrong name!")
            tester.assert(ws_protfield.m_abbr, "smp.someField", "Wrong filter!")
            tester.assert(ws_protfield.m_size, 42, "Wrong size!")
            tester.assert(ws_protfield.m_type, "string", "Wrong type!")
        end);
    
    unit_tests:addTest("Testing wireshark protofield construction with string() without override size", function()
            success,error_msg = pcall(wireshark.Protofield.string, "Some Field", "smp.someField");
            tester.assert(success, false, "This call should fail!")
        end);

    return unit_tests;
end

local unit_tests = createTests();
if is_standalone_test then
    tester.test(unit_tests);
    tester.printReport();
else
    return unit_tests
end

