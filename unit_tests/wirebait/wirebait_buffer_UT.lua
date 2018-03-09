
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

local function reverse_str(le_hex_str)
  local hex_str = "";
  for i=1,math.min(#le_hex_str/2,8) do
    hex_str = le_hex_str:sub(2*i-1,2*i) .. hex_str;
  end
  return hex_str;
end

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

unit_tests:addTest("Testing wireshark buffer:stringz()", function()
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
    tester.assert(wirebait.buffer.new("48454C4C"):uint(), 1212501068);
  end)

unit_tests:addTest("Testing wireshark buffer:uint64() (Big-Endian)", function()
    tester.assert(wirebait.buffer.new("6D45D89F55C23601"):uint64(), 7873937702377371137);
  end)

unit_tests:addTest("Testing wireshark buffer:uint64() (Big-Endian) Largest uint64", function()
    b = wirebait.buffer.new("FFFFFFFFFFFFFFFF");
    tester.assert(b:uint64(), 18446744073709551615); 
    tester.assert(b:uint64(), -1); 
  end)

unit_tests:addTest("Testing wireshark buffer:le_uint64() (Little-Endian) Largest uint64", function()
    b = wirebait.buffer.new("FFFFFFFFFFFFFFFF");
    tester.assert(b:le_uint64(), 18446744073709551615); 
    tester.assert(b:le_uint64(), -1); 
  end)

unit_tests:addTest("Testing wireshark buffer:le_uint() (Little-Endian)", function()
  tester.assert(wirebait.buffer.new("48454C4C"):le_uint(), 1280066888);
  end)

unit_tests:addTest("Testing wireshark buffer:le_uint64() (Little-Endian)", function()
    tester.assert(wirebait.buffer.new("48454C4C28520000"):le_uint64(), 90333032236360);
  end)

unit_tests:addTest("Testing wireshark buffer:int() (Big-Endian) Negative Number", function()
    tester.assert(wirebait.buffer.new("FFFF2852"):int(), -55214);
  end)

unit_tests:addTest("Testing wireshark buffer:int() (Big-Endian) Zero", function()
    tester.assert(wirebait.buffer.new("00000000"):int(), 0);
  end)

unit_tests:addTest("Testing wireshark buffer:int() (Big-Endian) -1", function()
    tester.assert(wirebait.buffer.new("FFFFFFFF"):int(), -1);
  end)

unit_tests:addTest("Testing wireshark buffer:int() (Big-Endian) Largest Negative Number", function()
    tester.assert(wirebait.buffer.new("80000000"):int(), -2147483648);
  end)

unit_tests:addTest("Testing wireshark buffer:int() (Big-Endian) Largest Positive Number", function()
    tester.assert(wirebait.buffer.new("7FFFFFFF"):int(), 2147483647);
  end)

unit_tests:addTest("Testing wireshark buffer:int64() (Big-Endian) Zero", function()
    tester.assert(wirebait.buffer.new("0000000000000000"):int64(), 0);
  end)

unit_tests:addTest("Testing wireshark buffer:int64() (Big-Endian) -1", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFFFF"):int64(), -1);
  end)

unit_tests:addTest("Testing wireshark buffer:int64() (Big-Endian) Large Negative Number", function()
    tester.assert(wirebait.buffer.new("EFFFFFFFFFFFFFFF"):int64(), -1152921504606846977);
  end)

unit_tests:addTest("Testing wireshark buffer:int64() (Big-Endian) Largest Negative Number", function()
    tester.assert(wirebait.buffer.new("8000000000000000"):int64(), -9223372036854775808);
  end)

unit_tests:addTest("Testing wireshark buffer:int64() (Big-Endian) Large Positive Number", function()
    tester.assert(wirebait.buffer.new("7FFFFFFFFFFFFFFF"):int64(), 9223372036854775807);
  end)

unit_tests:addTest("Testing wireshark buffer:le_int() (Little-Endian) Negative Number", function()
    tester.assert(wirebait.buffer.new("5228FFFF"):le_int(), -55214);
  end)

unit_tests:addTest("Testing wireshark buffer:le_int() (Little-Endian) Zero", function()
    tester.assert(wirebait.buffer.new("00000000"):le_int(), 0);
  end)

unit_tests:addTest("Testing wireshark buffer:le_int() (Little-Endian) -1", function()
    tester.assert(wirebait.buffer.new("FFFFFFFF"):le_int(), -1);
  end)

unit_tests:addTest("Testing wireshark buffer:le_int() (Little-Endian) Largest Negative Number", function()
    tester.assert(wirebait.buffer.new("00000080"):le_int(), -2147483648);
  end)

unit_tests:addTest("Testing wireshark buffer:le_int() (Little-Endian) Largest Positive Number", function()
    tester.assert(wirebait.buffer.new("FFFFFF7F"):le_int(), 2147483647);
  end)

unit_tests:addTest("Testing wireshark buffer:le_int64() (Little-Endian) Zero", function()
    tester.assert(wirebait.buffer.new("0000000000000000"):le_int64(), 0);
  end)

unit_tests:addTest("Testing wireshark buffer:le_int64() (Little-Endian) -1", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFFFF"):le_int64(), -1);
  end)

unit_tests:addTest("Testing wireshark buffer:le_int64() (Little-Endian) Large Negative Number", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFFEF"):le_int64(), -1152921504606846977);
  end)

unit_tests:addTest("Testing wireshark buffer:le_int64() (Little-Endian) Largest Negative Number", function()
    tester.assert(wirebait.buffer.new("0000000000000080"):le_int64(), -9223372036854775808);
  end)

unit_tests:addTest("Testing wireshark buffer:le_int64() (Little-Endian) Large Positive Number", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFF7F"):le_int64(), 9223372036854775807);
  end)

unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Single Precision) 1", function()
    tester.assert(wirebait.buffer.new("3F800000"):float(), 1);
  end) 

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Single Precision) 1", function()
    tester.assert(wirebait.buffer.new("0000803F"):le_float(), 1);
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

unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Double Precision) 1", function()
    tester.assert(wirebait.buffer.new("3FF0000000000000"):float(), 1);
  end) 
unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Double Precision) 1", function()
    tester.assert(wirebait.buffer.new("000000000000F03F"):le_float(), 1);
  end)
unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Double Precision) -2", function()
    tester.assert(wirebait.buffer.new("C000000000000000"):float(), -2);
  end)
unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Double Precision) 0", function()
    tester.assert(wirebait.buffer.new("0000000000000000"):float(), 0);
  end)
unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Double Precision) -0", function()
    tester.assert(wirebait.buffer.new("8000000000000000"):float(), 0);
  end) 
unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Double Precision) Infinity", function()
    tester.assert(wirebait.buffer.new("7FF0000000000000"):float(), math.huge);
  end)
unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Double Precision) -Infinity", function()
    tester.assert(wirebait.buffer.new("FFF0000000000000"):float(), -math.huge);
  end) 

unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Double Precision) -Pi", function()
    tester.assert(wirebait.buffer.new("C00921FB54442D18"):float(), -math.pi);
  end) 

unit_tests:addTest("Testing wireshark buffer:float() (Big-Endian Double Precision) Pi", function()
    tester.assert(wirebait.buffer.new("400921FB54442D18"):float(), math.pi);
  end)

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Single Precision) -2", function()
    tester.assert(wirebait.buffer.new("000000C0"):le_float(), -2);
  end) 

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Single Precision) 0", function()
    tester.assert(wirebait.buffer.new("00000000"):le_float(), 0);
  end) 

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Single Precision) -0", function()
    tester.assert(wirebait.buffer.new("00000080"):le_float(), 0);
  end)

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Single Precision) Infinity", function()
    tester.assert(wirebait.buffer.new("0000807F"):le_float(), math.huge);
  end) 

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Single Precision) -Infinity", function()
    tester.assert(wirebait.buffer.new("000080FF"):le_float(), -math.huge);
  end) 

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Single Precision) -0.15625", function()
    tester.assert(wirebait.buffer.new("000020BE"):le_float(), -0.15625);
  end) 

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Single Precision) 0.15625", function()
    tester.assert(wirebait.buffer.new("0000203E"):le_float(), 0.15625);
  end)

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Double Precision) -2", function()
    tester.assert(wirebait.buffer.new("00000000000000C0"):le_float(), -2);
  end) 

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Double Precision) 0", function()
    tester.assert(wirebait.buffer.new("0000000000000000"):le_float(), 0);
  end) 

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Double Precision) -0", function()
    tester.assert(wirebait.buffer.new("0000000000000080"):le_float(), 0);
  end)

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Double Precision) Infinity", function()
    tester.assert(wirebait.buffer.new("000000000000F07F"):le_float(), math.huge);
  end) 

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Double Precision) -Infinity", function()
    tester.assert(wirebait.buffer.new("000000000000F0FF"):le_float(), -math.huge);
  end) 

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Double Precision) -Pi", function()
    tester.assert(wirebait.buffer.new("182D4454FB2109C0"):le_float(), -math.pi);
  end) 

unit_tests:addTest("Testing wireshark buffer:le_float() (Little-Endian Double Precision) Pi", function()
    tester.assert(wirebait.buffer.new("182D4454FB210940"):le_float(), math.pi);
  end)

unit_tests:addTest("Testing wireshark buffer:ipv4() (Big-Endian) 192.168.0.1", function()
    tester.assert(wirebait.buffer.new("C0A80001"):ipv4(), "192.168.0.1");
  end)

unit_tests:addTest("Testing wireshark buffer:le_ipv4() (Little-Endian) 192.168.0.1", function()
    tester.assert(wirebait.buffer.new("0100A8C0"):le_ipv4(), "192.168.0.1");
  end)

unit_tests:addTest("Testing wireshark buffer:eth() (Big-Endian) EC:08:6B:70:36:82", function()
    tester.assert(wirebait.buffer.new("EC086B703682"):eth(), "EC:08:6B:70:36:82");
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

unit_tests:addTest("Testing wireshark buffer:bitfield(0,8) = 255", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFFFF"):bitfield(0,8), 255);
  end)

unit_tests:addTest("Testing wireshark buffer:bitfield(0,16) = 65535", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFFFF"):bitfield(0,16), 65535);
  end)

unit_tests:addTest("Testing wireshark buffer:bitfield(0,32) = 4294967295", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFFFF"):bitfield(0,32), 4294967295);
  end)

unit_tests:addTest("Testing wireshark buffer:bitfield(0,33) = 8589934591", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFFFF"):bitfield(0,33), 8589934591);
  end)

unit_tests:addTest("Testing wireshark buffer:bitfield(0,56) = 72057594037927935", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFFFF"):bitfield(0,56), 72057594037927935);
  end)

unit_tests:addTest("Testing wireshark buffer:bitfield(0,57) = 144115188075855871", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFFFF"):bitfield(0,57), 144115188075855871);
  end)

unit_tests:addTest("Testing wireshark buffer:bitfield(0,58) = 288230376151711743", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFFFF"):bitfield(0,58), 288230376151711743);
  end)

unit_tests:addTest("Testing wireshark buffer:bitfield(0,63) = 9223372036854775807", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFFFF"):bitfield(0,63), 9223372036854775807);
  end)

unit_tests:addTest("Testing wireshark buffer:bitfield(0,64) = -1", function()
    tester.assert(wirebait.buffer.new("FFFFFFFFFFFFFFFF"):bitfield(0,64), -1);
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

