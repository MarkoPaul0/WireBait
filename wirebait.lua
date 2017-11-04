
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
local function newWirebaitTree(wireshark_tree, buffer, position, parent)
    local wirebait_tree = {
        m_wireshark_tree = wireshark_tree;
        m_buffer = buffer;
        m_position = position or 0;
        m_end_position = (position or 0) + buffer:len();
        m_parent = parent or self;
    }
    
    local getParent = function()
        return m_wirebait_tree.m_parent;
    end
    
    local getWiresharkTree = function ()
        return wirebait_tree.m_wireshark_tree;
    end
    
    local getBuffer = function()
        return wirebait_tree.m_buffer;
    end

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
        __is_wirebait_struct = true, --all wirebait data should have this flag so as to know their type
        __wirebait_type_name = "WirebaitTree",
        position = getPosition,
        skip = skip,
        wiresharkTree = getWiresharkTree,
        __buffer = getBuffer,
        parent = getParent
    }
end


local function newWirebaitTree_overload(arg1, ...)
    if arg1.__is_wirebait_struct then
        wirebait_tree = arg1;
        return newWirebaitTree(wirebait_tree.wiresharkTree(),wirebait_tree.__buffer(), wirebait_tree.position(), wirebait_tree.parent())
    else
        return newWirebaitTree(arg1, unpack({...}));
    end
end


-- # Wirebait Field
local function newWirebaitField()
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
    field = {
        new = newWirebaitField
    },
    tree = {
        new = newWirebaitTree_overload
    }
}






--TEST
local buffer = {
    len = function()
        return 10;
    end
}

--local ws_test_tree = {
--        len = function ()
--            return 10;
--        end
--    }

--print(ws_test_tree:len())

ws_test_tree = { tree = true}

tree = wirebait.tree.new(ws_test_tree, buffer, 1);

print("old position " .. tree:position())
tree:skip(2)
print("new position " .. tree:position())
