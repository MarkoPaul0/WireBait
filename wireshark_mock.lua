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

local wireshark_mock = { treeitem = {}, buffer = {} };

function wireshark_mock.treeitem.new() 
    local treeitem = {
        m_length = 0
    }

    function treeitem:set_len(L)
        self.m_length = L;
    end

    --Not available in the API, here for testing
    function treeitem:get_len()
        return self.m_length
    end

    return treeitem;
end

function wireshark_mock.buffer.new(size)
    return {
        m_length = size or 0,

        len = function()
            return m_length
        end
    }
end

return wireshark_mock;


