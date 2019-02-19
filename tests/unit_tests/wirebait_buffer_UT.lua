--[[
    WireBait for wirebait is a lua package to help write Wireshark 
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
local tester = tester or require("tests.tester")
local wirebait = require("wirebait")

--[[ All variables here need to be kept local, however the unit test framework will run
each individual test function added with UnitTestsSet:addTest() in its own environment,
therefore forgetting the local keyword will not have a negative impact.
]]--
--Creating unit tests
local unit_tests = tester.newUnitTestsSet("wirebait Buffer Unit Tests");

unit_tests:addTest("Testing wirebait buffer construction", function()
    local b = wirebait.buffer.new("A0102FB1");
    tester.assert(b.m_data_as_hex_str, "A0102FB1", "Wrong underlying data");
    tester.assert(b:len(), 4, "Wrong size after construction")
  end);

unit_tests:addTest("Testing wirebait buffer construction with empty string", function()
    local b = wirebait.buffer.new("");
    tester.assert(b.m_data_as_hex_str, "", "Wrong underlying data");
    tester.assert(b:len(), 0, "Wrong size after construction")
  end);

unit_tests:addTest("Testing wirebait buffer:len()", function() 
    tester.assert(wirebait.buffer.new("4845"):len(), 2, "Wrong byte length");
  end)

unit_tests:addTest("Testing wirebait buffer:string()", function()
    tester.assert(wirebait.buffer.new("48454C4C4F20574F524C44"):string(),"HELLO WORLD", "Wrong result.");
  end)

unit_tests:addTest("Testing wirebait buffer:stringz()", function()
    tester.assert(wirebait.buffer.new("48454C4C4F20574F524C440032b4b1b34b2b"):stringz(),"HELLO WORLD", "Wrong result.");
  end)

unit_tests:addTest("Testing wirebait buffer(pos,len)", function()
    local b = wirebait.buffer.new("48454C4C4F20574F524C440032b4b1b34b2b");
    tester.assert(b(6,5):len(), 5, "Wrong size.");
    tester.assert(b(6,5):string(), "WORLD");
    tester.assert(b(0,5):len(), 5, "Wrong size.");
    tester.assert(b(0,5):string(), "HELLO");
  end)

unit_tests:addTest("Testing wirebait buffer:ipv4() (Big-Endian) 192.168.0.1", function()
    tester.assert(wirebait.buffer.new("C0A80001"):ipv4(), "192.168.0.1");
  end)

unit_tests:addTest("Testing wirebait buffer:le_ipv4() (Little-Endian) 192.168.0.1", function()
    tester.assert(wirebait.buffer.new("0100A8C0"):le_ipv4(), "192.168.0.1");
  end)

unit_tests:addTest("Testing wirebait buffer:eth() (Big-Endian) ec:08:6b:70:36:82", function()
    tester.assert(wirebait.buffer.new("EC086B703682"):eth(), "ec:08:6b:70:36:82");
  end)

unit_tests:addTest("Testing wirebait buffer:__guid() = 48454c4c-4f20-574f-524c-440032b4b1b3", function()
    tester.assert(wirebait.buffer.new("48454C4C4F20574F524C440032b4b1b3"):__guid(), "48454c4c-4f20-574f-524c-440032b4b1b3");
  end)

unit_tests:addTest("Testing wirebait buffer(pos,len)", function()
    local b = wirebait.buffer.new("48454C4C4F20574F524C440032b4b1b34b2b");
    tester.assert(b(6,5):len(), 5, "Wrong size.");
    tester.assert(b(6,5):string(), "WORLD");
    tester.assert(b(0,5):len(), 5, "Wrong size.");
    tester.assert(b(0,5):string(), "HELLO");
  end)

if is_standalone_test then
  tester.test(unit_tests);
  tester.printReport();
else
  return unit_tests
end

