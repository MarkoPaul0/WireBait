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
local tester = tester or require("unit_tests.tester")
local wirebait = require("wirebait")

--[[IMPORTANT NOTE: a simple and easy way to come up with test cases when testing Int64 addition is to use wolfram alpha
for instance [0xFFFFFFCDEDF1 + 0x1234FF24FF01](https://www.wolframalpha.com/input/?i=0xFFFFFFCDEDF1+%2B+0x1234FF24FF01) ]]

--[[ All variables here need to be kept local, however the unit test framework will run
each individual test function added with UnitTestsSet:addTest() in its own environment,
therefore forgetting the local keyword will not have a negative impact.
]]--
--Creating unit tests
local unit_tests = tester.newUnitTestsSet("wirebait Int64 Unit Tests");

local UINT32_MAX  = 0xFFFFFFFF;
local SIGN_MASK   = 0X80000000;

local function to2sComplement(num)
  return num >= 0 and num or ~num + 1;
end

unit_tests:addTest("Testing wirebait Int64.new(low_num)", function()
    local int_64 = wirebait.Int64.new(1);
    tester.assert(int_64.m_low_word, 1, "Wrong low_word value!");
    tester.assert(int_64.m_high_word, 0, "Wrong high_word value!");
    tester.assert(tostring(int_64), "1", "Wrong decimal string value!");
  end);

unit_tests:addTest("Testing wirebait Int64.new(NEGATIVE low_num)", function()
    local success, error_msg = pcall(wirebait.Int64.new, -1);
    tester.assert(success, false, "Int64.new(-1) should fail!");
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "Int64.new(num), num must be a positive 32 bit integer!", "Wrong error message!");
  end);

unit_tests:addTest("Testing wirebait Int64.new(NAN low_num)", function()
    local success, error_msg = pcall(wirebait.Int64.new, "not a number");
    tester.assert(success, false, "Int64.new(\"not a number\") should fail!");
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "Int64.new(num), num must be a positive 32 bit integer!", "Wrong error message!");
  end);

unit_tests:addTest("Testing wirebait Int64.new(NIL low_num)", function()
    local success, error_msg = pcall(wirebait.Int64.new);
    tester.assert(success, false, "Int64.new(nil) should fail!");
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "Int64.new(num), num must be a positive 32 bit integer!", "Wrong error message!");
  end);

unit_tests:addTest("Testing wirebait Int64.new(TOO LARGE low_num)", function()
    local success, error_msg = pcall(wirebait.Int64.new, UINT32_MAX + 1);
    tester.assert(success, false, "Int64.new(UINT32_MAX + 1) should fail!");
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "Int64.new(num), num must be a positive 32 bit integer!", "Wrong error message!");
  end);

unit_tests:addTest("Testing wirebait Int64.new(low_num, high_num)", function()
    local int_64 = wirebait.Int64.new(1,2);
    tester.assert(int_64.m_low_word, 1, "Wrong low_word value!");
    tester.assert(int_64.m_high_word, 2, "Wrong high_word value!");
    tester.assert(tostring(int_64), "8589934593", "Wrong decimal string value!");
  end);

unit_tests:addTest("Testing wirebait Int64.new(low_num, NEGATIVE high_num)", function()
    local success, error_msg = pcall(wirebait.Int64.new, 1, -1);
    tester.assert(success, false, "Int64.new(1, -1) should fail!");
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "Int64.new(num, high_num): when provided, high_num must be a positive 32 bit integer!", "Wrong error message!");
  end);

unit_tests:addTest("Testing wirebait Int64.new(low_num, NAN high_num)", function()
    local success, error_msg = pcall(wirebait.Int64.new, 1, "not a number");
    tester.assert(success, false, "Int64.new(1, \"not a number\") should fail!");
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "Int64.new(num, high_num): when provided, high_num must be a positive 32 bit integer!", "Wrong error message!", "Wrong error message!");
  end);

unit_tests:addTest("Testing wirebait Int64.new(low_num, TOO LARGE high_num)", function()
    local success, error_msg = pcall(wirebait.Int64.new, 1, UINT32_MAX + 1);
    tester.assert(success, false, "Int64.new(1, UINT32_MAX + 1) should fail!");
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "Int64.new(num, high_num): when provided, high_num must be a positive 32 bit integer!", "Wrong error message!", "Wrong error message!");
  end);

--unit_tests:addTest("Testing wirebait Int64.fromHex(00) = 0", function()
--    local int_64 = wirebait.Int64.fromHex("00");
--    tester.assert(int_64.m_low_word, 0, "Wrong low_word value!");
--    tester.assert(int_64.m_high_word, 0, "Wrong high_word value!");
--    tester.assert(tostring(int_64), "0", "Wrong decimal string value!");
--  end);

--unit_tests:addTest("Testing wirebait Int64.fromHex(0000000000) = 0", function()
--    local int_64 = wirebait.Int64.fromHex("0000000000");
--    tester.assert(int_64.m_low_word, 0, "Wrong low_word value!");
--    tester.assert(int_64.m_high_word, 0, "Wrong high_word value!");
--    tester.assert(tostring(int_64), "0", "Wrong decimal string value!");
--  end);

--unit_tests:addTest("Testing wirebait Int64.fromHex(FFFFFFFFFFFFFFFF) = Int64_max", function()
--    local int_64 = wirebait.Int64.fromHex("FFFFFFFFFFFFFFFF");
--    tester.assert(int_64.m_low_word, UINT32_MAX, "Wrong low_word value!");
--    tester.assert(int_64.m_high_word, UINT32_MAX, "Wrong high_word value!");
--    tester.assert(tostring(int_64), "18446744073709551615", "Wrong decimal string value!");
--  end);

--unit_tests:addTest("Testing wirebait Int64.fromHex(FFFFFFFF) = uint32_max", function()
--    local int_64 = wirebait.Int64.fromHex("FFFFFFFF");
--    tester.assert(int_64.m_low_word, UINT32_MAX, "Wrong low_word value!");
--    tester.assert(int_64.m_high_word, 0, "Wrong high_word value!");
--    tester.assert(tostring(int_64), "4294967295", "Wrong decimal string value!");
--  end);

--unit_tests:addTest("Testing wirebait Int64.fromHex(00000000FFFFFFFF) = uint32_max", function()
--    local int_64 = wirebait.Int64.fromHex("00000000FFFFFFFF");
--    tester.assert(int_64.m_low_word, UINT32_MAX, "Wrong low_word value!");
--    tester.assert(int_64.m_high_word, 0, "Wrong high_word value!");
--    tester.assert(tostring(int_64), "4294967295", "Wrong decimal string value!");
--  end);

--unit_tests:addTest("Testing wirebait Int64.fromHex(FFFFFFFF00000000) = 18446744069414584320", function()
--    local int_64 = wirebait.Int64.fromHex("FFFFFFFF00000000");
--    tester.assert(int_64.m_low_word, 0, "Wrong low_word value!");
--    tester.assert(int_64.m_high_word, UINT32_MAX, "Wrong high_word value!");
--    tester.assert(tostring(int_64), "18446744069414584320", "Wrong decimal string value!");
--  end);

--unit_tests:addTest("Testing wirebait Int64.fromHex(F1FAB2DC0143005F) = 17436445565302014047", function()
--    local int_64 = wirebait.Int64.fromHex("F1FAB2DC0143005F");
--    tester.assert(int_64.m_low_word, 0x0143005F, "Wrong low_word value!");
--    tester.assert(int_64.m_high_word, 0xF1FAB2DC, "Wrong high_word value!");
--    tester.assert(tostring(int_64), "17436445565302014047", "Wrong decimal string value!");
--  end);

unit_tests:addTest("Testing wirebait Int64.max()", function()
    local int_64 = wirebait.Int64.max();
    tester.assert(int_64.m_low_word, UINT32_MAX, "Wrong low_word value!");
    tester.assert(int_64.m_high_word, 0x7FFFFFFF, "Wrong high_word value!");
    tester.assert(tostring(int_64), "9223372036854775807", "Wrong decimal string value!");
  end);

unit_tests:addTest("Testing wirebait Int64.min()", function()
    local int_64 = wirebait.Int64.min();
    tester.assert(int_64.m_low_word, 0, "Wrong low_word value!");
    tester.assert(int_64.m_high_word, SIGN_MASK, "Wrong high_word value!");
    tester.assert(tostring(int_64), "-9223372036854775808", "Wrong decimal string value!");
  end);

unit_tests:addTest("Testing wirebait Int64, 1 + 1 = 2", function()
    local int_64 = wirebait.Int64.new(1) + wirebait.Int64.new(1);
    tester.assert(tostring(int_64), "2", "Wrong addition result!");
  end);

unit_tests:addTest("Testing wirebait Int64, UINT32_MAX + 1 = 4294967296", function()
    local int_64 = wirebait.Int64.new(UINT32_MAX) + wirebait.Int64.new(1);
    tester.assert(tostring(int_64), "4294967296", "Wrong addition result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1 + 0xFF24FF01 = 8572300530", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1) + wirebait.Int64.new(0xFF24FF01);
    tester.assert(tostring(int_64), "8572300530", "Wrong addition result!");
  end);

unit_tests:addTest("Testing wirebait Int64, UINT32_MAX + UINT32_MAX = 8589934590", function()
    local int_64 = wirebait.Int64.new(UINT32_MAX) + wirebait.Int64.new(UINT32_MAX);
    tester.assert(tostring(int_64), "8589934590", "Wrong addition result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1/0xFFFF + 0xFF24FF01/0x1234 = 301493801643250", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1, 0xFFFF) + wirebait.Int64.new(0xFF24FF01, 0x1234);
    tester.assert(tostring(int_64), "301493801643250", "Wrong addition result!");
  end);

unit_tests:addTest("Testing wirebait Int64, Int64_MAX + 1 = - (Wraparound)", function()
    local int_64 = wirebait.Int64.new(UINT32_MAX, 0x7FFFFFFF) + wirebait.Int64.new(1);
    tester.assert(tostring(int_64), "-9223372036854775808", "Wrong addition result!");
  end);

--unit_tests:addTest("Testing wirebait Int64, Int64_MAX + 0xAF = 174 (Wraparound)", function()
--    local int_64 = wirebait.Int64.new(UINT32_MAX, UINT32_MAX) + wirebait.Int64.new(0xAF);
--    tester.assert(tostring(int_64), "174", "Wrong addition result!");
--  end);

--unit_tests:addTest("Testing wirebait Int64, Int64_MAX + 0x01FFFFFFFF = 8589934590 (Wraparound)", function()
--    local int_64 = wirebait.Int64.new(UINT32_MAX, UINT32_MAX) + wirebait.Int64.new(UINT32_MAX, 0x01);
--    tester.assert(tostring(int_64), "8589934590", "Wrong addition result!");
--  end);

--unit_tests:addTest("Testing wirebait Int64, Int64_MAX + 0xFFFFFFFF/0xFFFF = 281474976710654 (Wraparound)", function()
--    local int_64 = wirebait.Int64.new(UINT32_MAX, UINT32_MAX) + wirebait.Int64.new(UINT32_MAX, 0xFFFF);
--    tester.assert(tostring(int_64), "281474976710654", "Wrong addition result!");
--  end);

--unit_tests:addTest("Testing wirebait Int64, Int64_MAX + Int64_MAX = 18446744073709551614 (Wraparound)", function()
--    local int_64 = wirebait.Int64.new(UINT32_MAX, UINT32_MAX) + wirebait.Int64.new(UINT32_MAX, UINT32_MAX);
--    tester.assert(tostring(int_64), "18446744073709551614", "Wrong addition result!");
--  end);

unit_tests:addTest("Testing wirebait Int64, 0x04 - 0x02 = 2", function()
    local int_64 = wirebait.Int64.new(0x04) - wirebait.Int64.new(0x02);
    tester.assert(tostring(int_64), "2", "Wrong substraction result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0x02 - 0x03 = 18446744073709551615", function()
    local int_64 = wirebait.Int64.new(0x02) - wirebait.Int64.new(0x03);
    tester.assert(tostring(int_64), "-1", "Wrong substraction result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0x02 - 0x02 = 0", function()
    local int_64 = wirebait.Int64.new(0x02) - wirebait.Int64.new(0x02);
    tester.assert(tostring(int_64), "0", "Wrong substraction result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0x02 -  0x00000000/0x01 = 0", function()
    local int_64 = wirebait.Int64.new(0x02) - wirebait.Int64.new(0,1);
    tester.assert(tostring(int_64), "-4294967294", "Wrong substraction result!");
  end);

--unit_tests:addTest("Testing wirebait Int64, Int64_MAX - (Int64_MAX - 1) = 0", function()
--    local int_64 = wirebait.Int64.new(UINT32_MAX,UINT32_MAX) - wirebait.Int64.new(UINT32_MAX-1,UINT32_MAX);
--    tester.assert(tostring(int_64), "1", "Wrong substraction result!");
--  end);

--unit_tests:addTest("Testing wirebait Int64, (Int64_MAX - 1) - Int64_MAX = 0", function()
--    local int_64 = wirebait.Int64.new(UINT32_MAX-1,UINT32_MAX) - wirebait.Int64.new(UINT32_MAX,UINT32_MAX);
--    tester.assert(tostring(int_64), "18446744073709551615", "Wrong substraction result!");
--  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1/0xFFFF - 0xFF24FF01/0x1234 = 301493801643250", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1, 0xFFFF) - wirebait.Int64.new(0xFF24FF01, 0x1234);
    tester.assert(tostring(int_64), "261456145215216", "Wrong substraction result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1 & 0xFF24FF01 = 4278512897", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1):band(wirebait.Int64.new(0xFF24FF01));
    tester.assert(tostring(int_64), "4278512897", "Wrong AND result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1/0xFFFF & 0xFF24FF01/0x1234 = 20018826112257", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1, 0xFFFF):band(wirebait.Int64.new(0xFF24FF01, 0x1234));
    tester.assert(tostring(int_64), "20018826112257", "Wrong AND result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1/0xFFFF & 0xFF24FF01/0x1234 & 0x4DA3 = 19713", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1, 0xFFFF):band(wirebait.Int64.new(0xFF24FF01, 0x1234), wirebait.Int64.new(0x4DA3));
    tester.assert(tostring(int_64), "19713", "Wrong AND result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1 | 0xFF24FF01 = 4293787633", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1):bor(wirebait.Int64.new(0xFF24FF01));
    tester.assert(tostring(int_64), "4293787633", "Wrong OR result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1/0xFFFF | 0xFF24FF01/0x1234 = 281474975530993", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1, 0xFFFF):bor(wirebait.Int64.new(0xFF24FF01, 0x1234));
    tester.assert(tostring(int_64), "281474975530993", "Wrong OR result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1/0xFFFF | 0xFF24FF01/0x1234 | 0x4DA3 = 281474975530995", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1, 0xFFFF):bor(wirebait.Int64.new(0xFF24FF01, 0x1234), wirebait.Int64.new(0x4DA3));
    tester.assert(tostring(int_64), "281474975530995", "Wrong OR result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1 ~ 0xFF24FF01 = 15274736", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1):bxor(wirebait.Int64.new(0xFF24FF01));
    tester.assert(tostring(int_64), "15274736", "Wrong XOR result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1/0xFFFF ~ 0xFF24FF01/0x1234 = 261456149418736", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1, 0xFFFF):bxor(wirebait.Int64.new(0xFF24FF01, 0x1234));
    tester.assert(tostring(int_64), "261456149418736", "Wrong XOR result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1/0xFFFF ~ 0xFF24FF01/0x1234 ~ 0x4DA3 = 261456149438291", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1, 0xFFFF):bxor(wirebait.Int64.new(0xFF24FF01, 0x1234), wirebait.Int64.new(0x4DA3));
    tester.assert(tostring(int_64), "261456149438291", "Wrong XOR result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1/0xFFFF >> 2 = 70368743357308", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1, 0xFFFF):rshift(2);
    tester.assert(tostring(int_64), "70368743357308", "Wrong RIGHT-SHIFT result!");
  end);

unit_tests:addTest("Testing wirebait Int64, 0xFFCDEDF1/0xFFFF << 2 = 1125899893716932", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1, 0xFFFF):lshift(2);
    tester.assert(tostring(int_64), "1125899893716932", "Wrong LEFT-SHIFT result!");
  end);

unit_tests:addTest("Testing wirebait Int64, ~0xFFCDEDF1/0xFFFF = 1125899893716932", function()
    local int_64 = wirebait.Int64.new(0xFFCDEDF1, 0xFFFF0000):bnot();
    tester.assert(tostring(int_64), "281470685024782", "Wrong NOT result!");
  end);


if is_standalone_test then
  tester.test(unit_tests);
  tester.printReport();
else
  return unit_tests
end