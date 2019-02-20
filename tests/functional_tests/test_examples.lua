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
local tester = tester or require("tests.tester")
local wirebait = require("wirebaitlib");
----[[ All variables here need to be kept local, however the unit test framework will run
--each individual test function added with UnitTestsSet:addTest() in its own environment,
--therefore forgetting the local keyword will not have a negative impact.
--]]--
----Creating functional tests
local functional_tests = tester.newUnitTestsSet("Functional Tests on Examples");
local hide_dissection_output = true;

functional_tests:addTest("Ensuring demo_dissector.lua runs smoothly", function()
  if hide_dissection_output then
    io.write = function() end --silencing the ouptut before running the dissector
  end
  local test = dofile("example/demo_dissector.lua");
  wirebait:clear();
end);

functional_tests:addTest("Ensuring demo_dissector2.lua runs smoothly", function()
  if hide_dissection_output then
    io.write = function() end --silencing the ouptut before running the dissector
  end
  local test = dofile("example/demo_dissector2.lua");
  wirebait:clear();
end);

if is_standalone_test then
  tester.test(functional_tests);
  tester.printReport();
else
  return functional_tests
end
