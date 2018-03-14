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

local tester = { test_count = 0, fail_count = 0, success_count = 0};

--[[For forward compatibility past lua 5.1. Indeed starting from lua 5.2, setfenv() is no longer available]]
if tonumber(string.match(_VERSION, "%d.%d+"))*10 > 51 then 
	print("Backwards compatibility")
	function setfenv(fn, env)
		local i = 1
		repeat
			local name = debug.getupvalue(fn, i)
			if name == "_ENV" then
				debug.upvaluejoin(fn, i, (function() return env end), 1)
				break
			end
			i = i + 1
		until name == "_ENV" or not name;
		return fn
	end
end

function tester.newUnitTestsSet(set_name)
	local unit_tests_set = { 
		name = set_name or "Unknown unit tests", 
		tests = {} 
	}
	function unit_tests_set:addTest(test_name, test_func)
		local newgt = {}        -- create new environment
		setmetatable(newgt, {__index = _G}) -- have the new environment inherits from the current one to garanty access to standard functions
		setfenv(test_func, newgt)    -- set the new environment for the test function so as to prevent the test function to "contaminate" the global namespace
		self.tests[#self.tests+1] = {name = test_name, func=test_func};
	end
	return unit_tests_set;
end

--runs the provided function, prints OK is a success, FAIL! otherwise with a detail of the error
function tester.runTest(func) 
    tester.test_count = tester.test_count + 1
    local status,err = pcall(func)
    if status then
        io.stdout:write("\tOK\n")
        tester.success_count = tester.success_count + 1;
    else
        if err and err:find(": _%[") then --if err comes from tester.assert
            err = err:sub(err:find(": _%[")+3)
        end
        io.stdout:write("\tFAIL! " .. (err or "") .."\n")
        tester.fail_count = tester.fail_count + 1;
    end
end

--runs all unit tests in a unit test set
function tester.test(unit_tests_set) --iterate through a set of unit tests
    io.stdout:write("\n>>>> " .. string.upper(unit_tests_set.name) .. "\n");
    local index = 0;
    for test_number,test in pairs(unit_tests_set.tests) do 
        if type(test.func) == 'function' then
            io.stdout:write(string.format("%-5d %-77s", index, test.name))
            tester.runTest(test.func);
            index = index + 1;
        end
    end
end

function tester.assert(val, expected_val, msg)
    if val ~= expected_val then 
        local debug_info = debug.getinfo(2)
        local filename = debug_info.source:match("^.+/(.+)$")
        local line_no = debug_info.currentline     

        local err_msg = "";
        if msg then
            err_msg = "_[" .. filename .. ":" .. line_no .. "] Expected '" .. tostring(expected_val) .. "' but got '" .. tostring(val) .. "'. (" .. msg .. ")";
        else
            err_msg = "_[" .. filename .. ":" .. line_no .. "] Expected '" .. tostring(expected_val) .. "' but got '" .. tostring(val) .. "'";
        end
        error(err_msg)
    end
end


function tester.printReport()
    print("\n------------- UNIT TESTS RESULTS -------------")
    print("  Tests run: " .. tester.test_count)
    print("   Tests ok: " .. tester.success_count)
    local warning_appending = "";
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
