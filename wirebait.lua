
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


-- # Wirebait Tree
local function newWireBaitTree(wireshark_tree, buffer, position)
    local wirebait_tree = {
        m_wireshark_tree = wireshark_tree;
        m_buffer = buffer;
        m_position = position or 0;
        m_end_position = (position or 0) + buffer:len();
    }
    
    local getPosition = function()
        return wirebait_tree.m_position;
    end
    
    local skip = function(self, byte_count)
        assert(wirebait_tree.m_position + byte_count <= wirebait_tree.m_end_position , "Trying to skip more bytes than available in buffer managed by wirebait tree!")
        wirebait_tree.m_position = wirebait_tree.m_position + byte_count;
    end
    
    local setLength = function(self, L)
        wirebait_tree.m_wireshark_tree:setLength(L);
    end
    
    local addField = function (self, wirebait_field)
        
    end
    
    local addTree = function (self, length)
        sub_ws_tree = wirebait_tree.m_wireshark_tree:add(self.m_position, length or 1);
        --newWireBaitTree()
    end
    
    return {
        position() = getPosition,
        skip = skip
        }
end

-- # Wirebait Field
local function newWireBaitField()
    local wirebait_field = {
            m_wireshark_field,
            m_name,
            m_size
        }
        
    local getName = function()
        return wirebait_field.m_name;
    end
    
    local getSize = function()
        return wirebait_field.m_size
    end
    
        
    return {
        name = getName(),
        size = getSize()
        };
end



--All functions available in wirebait package are named here
wirebait = {
    field = {new = newWireBaitField},
    tree = {new = newWireBaitTree}
    }
