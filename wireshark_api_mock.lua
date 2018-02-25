--[[
    lua code that mocks wireshark lua api to test wirebait
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

local wireshark_mock = { wirebait_hanlde = nil, Proto = {}, ProtoField = {}, treeitem = {}, buffer = {}, base = { DEC = {} }};



--mapping diffent types to the same mock constructor
wireshark_mock.ProtoField.uint8 = function(name, abbr) return wireshark_mock.ProtoField.new(name, abbr, "uint8") end
wireshark_mock.ProtoField.uint16 = function(name, abbr) return wireshark_mock.ProtoField.new(name, abbr, "uint16") end
wireshark_mock.ProtoField.uint32 = function(name, abbr) return wireshark_mock.ProtoField.new(name, abbr, "uint32") end
wireshark_mock.ProtoField.uint64 = function(name, abbr) return wireshark_mock.ProtoField.new(name, abbr, "uint64") end
wireshark_mock.ProtoField.string = function(name, abbr, size) return wireshark_mock.ProtoField.new(name, abbr, "string", size) end

function wireshark_mock.setupWiresharkEnvironment() --sets up variable in current scope
    base = wireshark_mock.base;
    ProtoField = wireshark_mock.ProtoField;
    Proto = wireshark_mock.Proto.new;
end

return wireshark_mock;


