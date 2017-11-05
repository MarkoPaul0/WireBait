--[[
    Provides a very small testing framework without any dependency
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

local tester = { test_count = 0, fail_count = 0, success_count = 0};

--runs the provided function, prints OK is a success, FAIL! otherwise with a detail of the error
function tester.runTest(func) 
    tester.test_count = tester.test_count + 1;
    status,err = pcall(func)
    if status then
        io.stdout:write("\tOK\n")
        tester.success_count = tester.success_count + 1;
    else
        io.stdout:write("\tFAIL! " .. (err or "") .."\n")
        tester.fail_count = tester.fail_count + 1;
    end
end

function tester.test(...)
        unit_tests = ...;
        for test_name,test_func in pairs(unit_tests) do 
            if type(test_func) == 'function' then
                tester.runTest(test_func);
            end
        end
end


function tester.printReport()
    print("\n------------- UNIT TESTS RESULTS -------------")
    print("  Tests run: " .. tester.test_count)
    print("   Tests ok: " .. tester.success_count)
    if tester.fail_count > 0 then 
        warning_appendix = "\t\t\t  /!\\/!\\"
    else
        warning_appendix = "";
    end
    print("Tests fails: " .. tester.fail_count .. warning_appendix)
    assert(tester.test_count == (tester.success_count + tester.fail_count), "Tests counts do not add up!")
    print("----------------------------------------------")
end

return tester;
