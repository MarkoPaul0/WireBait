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


--# UNIT TESTING 
tester = require("unit_tests.tester")
print("\nRunning all unit tests")

--# WIREBAIT TESTS
tester.test(dofile("unit_tests/test_files/wirebait_protofield_UT.lua"))
tester.test(dofile("unit_tests/test_files/wirebait_buffer_UT.lua"))
tester.test(dofile("unit_tests/test_files/wirebait_uint64_UT.lua"))

tester.printReport();