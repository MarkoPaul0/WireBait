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

unit_tests:addTest("Wirebait protofield construction with new(name, abbr, type)", function()
    local proto_field = wirebait.ProtoField.new("Some Field", "smp.someField", "uint16")
    tester.assert(proto_field.m_name, "Some Field", "Wrong name!")
    tester.assert(proto_field.m_abbr, "smp.someField", "Wrong filter!")
    tester.assert(proto_field.m_type, "uint16", "Wrong type!")
    tester.assert(proto_field.m_value_string, nil, "Wrong value_string!")    
    tester.assert(proto_field.m_base, nil, "Wrong base!")
    tester.assert(proto_field.m_mask, nil, "Wrong mask!")
    tester.assert(proto_field.m_description, nil, "Wrong description!")
  end);

unit_tests:addTest("Wirebait protofield construction with new(name, abbr, ftype, value_string, fbase, mask, desc)", function()
    local value_string = {[0x01]="Value"};
    local proto_field = wirebait.ProtoField.new("Some Field", "smp.someField", "uint16", value_string, base.HEX, 0xFFFF, "Some description")
    tester.assert(proto_field.m_name, "Some Field", "Wrong name!")
    tester.assert(proto_field.m_abbr, "smp.someField", "Wrong filter!")
    tester.assert(proto_field.m_type, "uint16", "Wrong type!")
    tester.assert(proto_field.m_value_string, value_string, "Wrong value_string!")    
    tester.assert(proto_field.m_base, base.HEX, "Wrong base!")
    tester.assert(proto_field.m_mask, 0xFFFF, "Wrong mask!")
    tester.assert(proto_field.m_description, "Some description", "Wrong description!")
  end);

unit_tests:addTest("Wirebait protofield construction with new(NIL name, abbr, ftype, value_string, fbase, mask, desc)", function()
    local success,error_msg = pcall(wirebait.ProtoField.new, nil, "smp.someField", "uint16", nil, base.HEX, 0xFFFF, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "ProtoField name, abbr, and type must not be nil!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with new(INVALID name, abbr, ftype, value_string, fbase, mask, desc)", function()
    local invalid_name = 42;
    local success,error_msg = pcall(wirebait.ProtoField.new, invalid_name, "smp.someField", "uint16", nil, base.HEX, 0xFFFF, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "ProtoField name, abbr, and type must be strings!", "Invalid error message!")
  end);



unit_tests:addTest("Wirebait protofield construction with new(name, NIL abbr, ftype, value_string, fbase, mask, desc)", function()
    local success,error_msg = pcall(wirebait.ProtoField.new, "Some Field", nil, "uint16", nil, base.HEX, 0xFFFF, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "ProtoField name, abbr, and type must not be nil!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with new(name, INVALID abbr, ftype, value_string, fbase, mask, desc)", function()
    local invalid_abbr = 42;
    local success,error_msg = pcall(wirebait.ProtoField.new, "Some Field", invalid_abbr, "uint16", nil, base.HEX, 0xFFFF, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "ProtoField name, abbr, and type must be strings!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with new(name, abbr, NIL ftype, value_string, fbase, mask, desc)", function()
    local success,error_msg = pcall(wirebait.ProtoField.new, "Some Field", "smp.someField", nil, nil, base.HEX, 0xFFFF, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "ProtoField name, abbr, and type must not be nil!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with new(name, abbr, INVALID ftype, value_string, fbase, mask, desc)", function()
    local invalid_ftype = 42;
    local success,error_msg = pcall(wirebait.ProtoField.new, "Some Field", "smp.someField", invalid_ftype, nil, base.HEX, 0xFFFF, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "ProtoField name, abbr, and type must be strings!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with new(name, abbr, ftype, INVALID value_string, fbase, mask, desc)", function()
    local invalid_value_string = "invalid";
    local success,error_msg = pcall(wirebait.ProtoField.new, "Some Field", "smp.someField", "uint16", invalid_value_string, base.HEX, 0xFFFF, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "The optional ProtoField valuestring must be a table!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with new(name, abbr, ftype, value_string, INVALID fbase, mask, desc)", function()
    local invalid_base = "invalid";
    local success,error_msg = pcall(wirebait.ProtoField.new, "Some Field", "smp.someField", "uint16", nil, invalid_base, 0xFFFF, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "The optional ProtoField base must to be an integer!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with new(name, abbr, ftype, value_string, fbase, INVALID mask, desc)", function()
    local invalid_mask = "invalid";
    local success,error_msg = pcall(wirebait.ProtoField.new, "Some Field", "smp.someField", "uint16", nil, nil, invalid_mask, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "The optional ProtoField mask must to be an integer!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with uint8(abbr, name)", function()
    local proto_field = wirebait.ProtoField.uint8("smp.someField", "Some Field")
    tester.assert(proto_field.m_name, "Some Field", "Wrong name!")
    tester.assert(proto_field.m_abbr, "smp.someField", "Wrong filter!")
    tester.assert(proto_field.m_type, "uint8", "Wrong type!")
    tester.assert(proto_field.m_value_string, nil, "Wrong value_string!")    
    tester.assert(proto_field.m_base, nil, "Wrong base!")
    tester.assert(proto_field.m_mask, nil, "Wrong mask!")
    tester.assert(proto_field.m_description, nil, "Wrong description!")
  end);

unit_tests:addTest("Wirebait protofield construction with uint8(abbr, name, fbase, value_string, mask, desc)", function()
    local value_string = {[0x02]="Value2"};
    local proto_field = wirebait.ProtoField.uint8("smp.someField", "Some Field", base.DEC, value_string, 0x4B, "some other description")
    tester.assert(proto_field.m_name, "Some Field", "Wrong name!")
    tester.assert(proto_field.m_abbr, "smp.someField", "Wrong filter!")
    tester.assert(proto_field.m_type, "uint8", "Wrong type!")
    tester.assert(proto_field.m_value_string, value_string, "Wrong value_string!")    
    tester.assert(proto_field.m_base, base.DEC, "Wrong base!")
    tester.assert(proto_field.m_mask, 0x4B, "Wrong mask!")
    tester.assert(proto_field.m_description, "some other description", "Wrong description!")
  end);

unit_tests:addTest("Wirebait protofield construction with uint8(NIL abbr, name, fbase, value_string, mask, desc)", function()
    local success,error_msg = pcall(wirebait.ProtoField.uint8, nil, "Some Field", nil, nil, nil, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "ProtoField name, abbr, and type must not be nil!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with uint8(abbr, NIL name, fbase, value_string, mask, desc)", function()
    local success,error_msg = pcall(wirebait.ProtoField.uint8, "smp.someField", nil, nil, nil, nil, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "ProtoField name, abbr, and type must not be nil!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with uint8(INVALID abbr, name, fbase, value_string, mask, desc)", function()
    local invalid_abbr = 42;
    local success,error_msg = pcall(wirebait.ProtoField.uint8, invalid_abbr, "Some Field", nil, nil, nil, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "ProtoField name, abbr, and type must be strings!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with uint8(abbr, INVALID name, fbase, value_string, mask, desc)", function()
    local invalid_name = 42;
    local success,error_msg = pcall(wirebait.ProtoField.uint8, "smp.someField", invalid_name, nil, nil, nil, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "ProtoField name, abbr, and type must be strings!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with uint8(abbr, name, INVALID fbase, value_string, mask, desc)", function()
    local invalid_base = "invalid";
    local success,error_msg = pcall(wirebait.ProtoField.uint8, "smp.someField", "Some Field", invalid_base, nil, nil, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "The optional ProtoField base must to be an integer!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with uint8(abbr, name, fbase, INVALID value_string, mask, desc)", function()
    local invalid_value_string = "invalid";
    local success,error_msg = pcall(wirebait.ProtoField.uint8, "smp.someField", "Some Field", nil, invalid_value_string, nil, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "The optional ProtoField valuestring must be a table!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with uint8(abbr, name, fbase, value_string, INVALID mask, desc)", function()
    local invalid_mask = "invalid";
    local success,error_msg = pcall(wirebait.ProtoField.uint8, "smp.someField", "Some Field", nil, nil, invalid_mask, "Some description");
    tester.assert(success, false, "This call should fail!")
    error_msg = error_msg:sub(error_msg:find(": ")+2) --remove the prepended error location
    tester.assert(error_msg, "The optional ProtoField mask must to be an integer!", "Invalid error message!")
  end);

unit_tests:addTest("Wirebait protofield construction with uint16(abbr, name)", function()
    local proto_field = wirebait.ProtoField.uint16("smp.someField", "Some Field")
    tester.assert(proto_field.m_name, "Some Field", "Wrong name!")
    tester.assert(proto_field.m_abbr, "smp.someField", "Wrong filter!")
    tester.assert(proto_field.m_type, "uint16", "Wrong type!")
    tester.assert(proto_field.m_value_string, nil, "Wrong value_string!")    
    tester.assert(proto_field.m_base, nil, "Wrong base!")
    tester.assert(proto_field.m_mask, nil, "Wrong mask!")
    tester.assert(proto_field.m_description, nil, "Wrong description!")
  end);

unit_tests:addTest("Wirebait protofield construction with uint32(abbr, name)", function()
    local proto_field = wirebait.ProtoField.uint32("smp.someField", "Some Field")
    tester.assert(proto_field.m_name, "Some Field", "Wrong name!")
    tester.assert(proto_field.m_abbr, "smp.someField", "Wrong filter!")
    tester.assert(proto_field.m_type, "uint32", "Wrong type!")
    tester.assert(proto_field.m_value_string, nil, "Wrong value_string!")    
    tester.assert(proto_field.m_base, nil, "Wrong base!")
    tester.assert(proto_field.m_mask, nil, "Wrong mask!")
    tester.assert(proto_field.m_description, nil, "Wrong description!")
  end);

unit_tests:addTest("Wirebait protofield construction with uint64(abbr, name)", function()
    local proto_field = wirebait.ProtoField.uint64("smp.someField", "Some Field")
    tester.assert(proto_field.m_name, "Some Field", "Wrong name!")
    tester.assert(proto_field.m_abbr, "smp.someField", "Wrong filter!")
    tester.assert(proto_field.m_type, "uint64", "Wrong type!")
    tester.assert(proto_field.m_value_string, nil, "Wrong value_string!")    
    tester.assert(proto_field.m_base, nil, "Wrong base!")
    tester.assert(proto_field.m_mask, nil, "Wrong mask!")
    tester.assert(proto_field.m_description, nil, "Wrong description!")
  end);

unit_tests:addTest("Wirebait protofield construction with string(abbr, name)", function()
    local proto_field = wirebait.ProtoField.string("smp.someField", "Some Field")
    tester.assert(proto_field.m_name, "Some Field", "Wrong name!")
    tester.assert(proto_field.m_abbr, "smp.someField", "Wrong filter!")
    tester.assert(proto_field.m_type, "string", "Wrong type!")
    tester.assert(proto_field.m_value_string, nil, "Wrong value_string!")    
    tester.assert(proto_field.m_base, nil, "Wrong base!")
    tester.assert(proto_field.m_mask, nil, "Wrong mask!")
    tester.assert(proto_field.m_description, nil, "Wrong description!")
  end);

if is_standalone_test then
  tester.test(unit_tests);
  tester.printReport();
else
  return unit_tests
end

