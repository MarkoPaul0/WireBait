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

--[[
    When a user uses require("wirebaitlib"), this init.lua is loaded.

    The only module that needs to be directly exposed to the user when using wirebait is the DissectorRunner.
    This module will itself load all other necessary modules before loading and invoking the tested dissector.
]]

--[[
    The method setfenc is only available until Lua 5.1, so we define it here if it is not available
]]
if not setfenv  then
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

local WirebaitLib = require("wirebaitlib.dissector.DissectorRunner");
return WirebaitLib;