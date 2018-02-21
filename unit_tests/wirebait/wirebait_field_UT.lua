
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
local wirebait = require("wirebait.wirebait") 
ProtoField = wireshark.ProtoField; --make available Protofield globally


--[[ All variables here need to be kept local, however the unit test framework will run
each individual test function added with UnitTestsSet:addTest() in its own environment,
therefore forgetting the local keywork will not have a negative impact.
]]--
--Creating unit tests
local unit_tests = tester.newUnitTestsSet("Wirebait Field Unit Tests");

unit_tests:addTest("Testing wirebait field construction", function()
        wb_field = wirebait.field.new("smp.someUint32Field", "Some Uint32 Field", 4, "uint32");
        tester.assert(wb_field.filter(), "smp.someUint32Field", "Wrong filter!")
        tester.assert(wb_field.name(), "Some Uint32 Field", "Wrong name!")
        tester.assert(wb_field.size(), 4, "Wrong size!")
        tester.assert(wb_field.type(), "uint32", "Wrong filter!")
    end)

--    unit_tests:addTest("Testing wirebait field construction", function()
--        end)

--    unit_tests:addTest("Testing wirebait field construction", function()
--        end)


if is_standalone_test then
    tester.test(unit_tests);
    tester.printReport();
else
    return unit_tests
end

