
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


local function run_tests() --keeping everything in a local scope to prevent interferences if multiple unit test files are run
    wireshark = require("wirebait.test.wireshark_mock")
    wirebait = require("wirebait.wirebait")
    tester = tester or require("wirebait.unit_tests.tester")

    base = wireshark.base --make available base as a global variable
    Protofield = wireshark.Protofield; --make available Protofield globally

    local function test_new_tree()
        io.stdout:write("Testing wirebait tree creation...")
    end
    
    local function test_tree_skip()
        io.stdout:write("Testing wirebait tree:skip()...")
        assert(false, "ZER IZ A PROBLEM")
    end
    
    local function test_tree_addUint8()
        io.stdout:write("Testing wirebait tree:addUint8()...")
    end

--# Function running all the tests in that file
    local function run_local_tests()
        tester.test(test_new_tree);
        tester.test(test_tree_skip);
        tester.test(test_tree_addUint8);
    end
    
    return run_local_tests;
end

return { run = run_tests() } --simply call run() on the returned table to run the tests in that file