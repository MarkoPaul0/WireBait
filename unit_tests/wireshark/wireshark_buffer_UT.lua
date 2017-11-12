
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
local wireshark = require("wirebait.wireshark_api_mock")

--[[ All variables here need to be kept local, however the unit test framework will run
each individual test function added with UnitTestsSet:addTest() in its own environment,
therefore forgetting the local keywork will not have a negative impact.
]]--
--Creating unit tests
local unit_tests = tester.newUnitTestsSet("Wireshark Buffer Unit Tests");

unit_tests:addTest("Testing wireshark buffer construction", function()
        b = wireshark.buffer.new("A0102FB1");
        assert(b.m_data_as_hex_str == "A0102FB1", "Wrong underlying data");
        assert(b:len() == 4, "Wrong size after construction")
    end);

unit_tests:addTest("Testing wireshark buffer:string()", function()
        b = wireshark.buffer.new("48454C4C4F20574F524C44");
        tester.assert(b:string(),"HELLO WORLD", "Wrong result.");
    end)

unit_tests:addTest("Testing wireshark buffer:string()", function()
        b = wireshark.buffer.new("48454C4C4F20574F524C440032b4b1b34b2b");
        tester.assert(b:stringz(),"HELLO WORLD", "Wrong result.");
    end)

unit_tests:addTest("Testing wireshark buffer(pos,len)", function()
        b = wireshark.buffer.new("48454C4C4F20574F524C440032b4b1b34b2b");
        tester.assert(b(6,5):len(), 5, "Wrong size.");
        tester.assert(b(6,5):string(), "WORLD");
        tester.assert(b(0,5):len(), 5, "Wrong size.");
        tester.assert(b(0,5):string(), "HELLO");
    end)

unit_tests:addTest("Testing wireshark buffer:uint() (Big-Endian)", function()
        b = wireshark.buffer.new("48454C4C4F20574F524C440032b4b1b34b2b");
        tester.assert(b:uint(), 1212501068);
    end)

unit_tests:addTest("Testing wireshark buffer:le_uint() (Little-Endian)", function()
        b = wireshark.buffer.new("48454C4C4F20574F524C440032b4b1b34b2b");
        tester.assert(b:le_uint(), 1280066888);
    end)

unit_tests:addTest("Testing wireshark buffer:le_uint() (Little-Endian)", function()
        b = wireshark.buffer.new("48454C4C285200000000000000");
        tester.assert(b:le_uint64(), 90333032236360);
    end)


if is_standalone_test then
    tester.test(unit_tests);
    tester.printReport();
else
    return unit_tests
end

