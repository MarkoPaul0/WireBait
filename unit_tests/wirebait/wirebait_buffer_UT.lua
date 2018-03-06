
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
local tester = tester or require("unit_tests.tester")
local wirebait = require("wirebait")

--[[ All variables here need to be kept local, however the unit test framework will run
each individual test function added with UnitTestsSet:addTest() in its own environment,
therefore forgetting the local keyword will not have a negative impact.
]]--
--Creating unit tests
local unit_tests = tester.newUnitTestsSet("Wireshark Buffer Unit Tests");

unit_tests:addTest("Testing wireshark buffer construction", function()
    b = wirebait.buffer.new("A0102FB1");
    assert(b.m_data_as_hex_str == "A0102FB1", "Wrong underlying data");
    assert(b:len() == 4, "Wrong size after construction")
  end);

unit_tests:addTest("Testing wireshark buffer:string()", function()
    b = wirebait.buffer.new("48454C4C4F20574F524C44");
    tester.assert(b:string(),"HELLO WORLD", "Wrong result.");
  end)

unit_tests:addTest("Testing wireshark buffer:string()", function()
    b = wirebait.buffer.new("48454C4C4F20574F524C440032b4b1b34b2b");
    tester.assert(b:stringz(),"HELLO WORLD", "Wrong result.");
  end)

unit_tests:addTest("Testing wireshark buffer(pos,len)", function()
    b = wirebait.buffer.new("48454C4C4F20574F524C440032b4b1b34b2b");
    tester.assert(b(6,5):len(), 5, "Wrong size.");
    tester.assert(b(6,5):string(), "WORLD");
    tester.assert(b(0,5):len(), 5, "Wrong size.");
    tester.assert(b(0,5):string(), "HELLO");
  end)

unit_tests:addTest("Testing wireshark buffer:uint() (Big-Endian)", function()
    b = wirebait.buffer.new("48454C4C4F20574F524C440032b4b1b34b2b");
    tester.assert(b:uint(), 1212501068);
  end)

unit_tests:addTest("Testing wireshark buffer:uint64() (Big-Endian)", function()
    b = wirebait.buffer.new("6D45D89F55C23601574F524C440032b4b1b34b2b");
    tester.assert(b:uint64(), 7873937702377371137);
  end)

--[[ TODO: figure out why 64bit integer are problematic when dealing with really high values]]
unit_tests:addTest("Testing wireshark buffer:uint64() (Big-Endian) Largest uint64", function()
    b = wirebait.buffer.new("FFFFFFFFFFFFFFFF");
    tester.assert(b:uint64(), 18446744073709551615); 
  end)

unit_tests:addTest("Testing wireshark buffer:le_uint() (Little-Endian)", function()
    b = wirebait.buffer.new("48454C4C4F20574F524C440032b4b1b34b2b");
    tester.assert(b:le_uint(), 1280066888);
  end)

unit_tests:addTest("Testing wireshark buffer:le_uint64() (Little-Endian)", function()
    b = wirebait.buffer.new("48454C4C285200000000000000");
    tester.assert(b:le_uint64(), 90333032236360);
  end)

unit_tests:addTest("Testing wireshark buffer:int() (Big-Endian) Negative Number", function()
    b = wirebait.buffer.new("FFFF2852"); 
    tester.assert(b:int(), -55214);
  end)

unit_tests:addTest("Testing wireshark buffer:int() (Big-Endian) Zero", function()
    b = wirebait.buffer.new("00000000");
    tester.assert(b:int(), 0);
  end)

unit_tests:addTest("Testing wireshark buffer:int() (Big-Endian) -1", function()
    b = wirebait.buffer.new("FFFFFFFF");
    tester.assert(b:int(), -1);
  end)

unit_tests:addTest("Testing wireshark buffer:int() (Big-Endian) Largest Negative Number", function()
    b = wirebait.buffer.new("80000000");
    tester.assert(b:int(), -2147483648);
  end)

unit_tests:addTest("Testing wireshark buffer:int() (Big-Endian) Largest Positive Number", function()
    b = wirebait.buffer.new("7FFFFFFF");
    tester.assert(b:int(), 2147483647);
  end)

unit_tests:addTest("Testing wireshark buffer:int64() (Big-Endian) Zero", function()
    b = wirebait.buffer.new("0000000000000000");
    tester.assert(b:int64(), 0);
  end)

--[[This test fails]]
unit_tests:addTest("Testing wireshark buffer:int64() (Big-Endian) -1", function()
    b = wirebait.buffer.new("FFFFFFFFFFFFFFFF");
    tester.assert(b:int64(), -1);
  end)

unit_tests:addTest("Testing wireshark buffer:int64() (Big-Endian) Large Negative Number", function()
    b = wirebait.buffer.new("EFFFFFFFFFFFFFFF");
    tester.assert(b:int64(), -1152921504606846977);
  end)

unit_tests:addTest("Testing wireshark buffer:int64() (Big-Endian) Largest Negative Number", function()
    b = wirebait.buffer.new("8000000000000000");
    tester.assert(b:int64(), -9223372036854775808);
  end)

unit_tests:addTest("Testing wireshark buffer:int64() (Big-Endian) Large Positive Number", function()
    b = wirebait.buffer.new("7FFFFFFFFFFFFFFF");
    tester.assert(b:int64(), 9223372036854775807);
  end)

unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Single Precision) 1", function()
    tester.assert(wirebait.buffer.new("3F800000"):float(), 1);
  end) 

unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Single Precision) -2", function()
    tester.assert(wirebait.buffer.new("C0000000"):float(), -2);
  end) 

unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Single Precision) 0", function()
    tester.assert(wirebait.buffer.new("00000000"):float(), 0);
  end) 

unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Single Precision) -0", function()
    tester.assert(wirebait.buffer.new("80000000"):float(), 0);
  end) 

unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Single Precision) Infinity", function()
    tester.assert(wirebait.buffer.new("7F800000"):float(), math.huge);
  end) 

unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Single Precision) -Infinity", function()
    tester.assert(wirebait.buffer.new("FF800000"):float(), -math.huge);
  end) 

unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Single Precision) -0.15625", function()
    tester.assert(wirebait.buffer.new("BE200000"):float(), -0.15625);
  end) 

unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Single Precision) 0.15625", function()
    tester.assert(wirebait.buffer.new("3E200000"):float(), 0.15625);
  end)

unit_tests:addTest("Testing wireshark buffer:bitfield(11,3) = 4", function()
    tester.assert(wirebait.buffer.new("AB123FC350DDB12D"):bitfield(11,3), 4);
  end)

unit_tests:addTest("Testing wireshark buffer:bitfield(11,5) = 18", function()
    tester.assert(wirebait.buffer.new("AB123FC350DDB12D"):bitfield(11,5), 18);
  end)

unit_tests:addTest("Testing wireshark buffer:bitfield(0,8) = 171", function()
    tester.assert(wirebait.buffer.new("AB123FC350DDB12D"):bitfield(0,8), 171);
  end)

unit_tests:addTest("Testing wireshark buffer:bitfield(0,33) = 5740199814", function()
    tester.assert(wirebait.buffer.new("AB123FC350DDB12D"):bitfield(0,33), 5740199814);
  end)

unit_tests:addTest("Testing wireshark buffer:len()", function() 
    b = wirebait.buffer.new("4845");
    tester.assert(b:len(), 2, "Wrong length");
  end)

if is_standalone_test then
  tester.test(unit_tests);
  tester.printReport();
else
  return unit_tests
end

