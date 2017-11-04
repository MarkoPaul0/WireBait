
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
        m_parent = parent;
        m_is_root = not parent;
    }
    
    local getParent = function(self)
        return wirebait_tree.m_parent or self;
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
        --print("skipping on " .. tostring(wirebait_tree) .. "  " .. tostring(self))
        if not wirebait_tree.m_is_root then
            --print("yo " .. tostring(getParent()))
            getParent():skip(byte_count);
        end
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

    local public_interface = {
        __is_wirebait_struct = true, --all wirebait data should have this flag so as to know their type
        __wirebait_type_name = "WirebaitTree",
        position = getPosition,
        skip = skip,
        wiresharkTree = getWiresharkTree,
        __buffer = getBuffer,
        parent = getParent
    }
    
    --print("Public address: " .. tostring(public_interface));
    return public_interface;
end


local function newWirebaitTree_overload(arg1, ...)
    --for i in pairs(arg1) do print(i) end
    if arg1.__is_wirebait_struct then
        wirebait_tree = arg1;
        return newWirebaitTree(wirebait_tree.wiresharkTree(),wirebait_tree.__buffer(), wirebait_tree.position(), wirebait_tree)
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
        return 512;
    end
}

--local ws_test_tree = {
--        len = function ()
--            return 10;
--        end
--    }

--print(ws_test_tree:len())

ws_test_tree = { tree = true}

root_tree = wirebait.tree.new(ws_test_tree, buffer, 0);
print("root address " .. tostring(root_tree) .. " parent " .. tostring(root_tree:parent()))

--print("parent of root tree: " .. tostring(root_tree.parent()))

--print("old position " .. root_tree:position())
root_tree:skip(1)

child_tree = wirebait.tree.new(root_tree)
print("child address " .. tostring(child_tree) .. "\n")

print("old position root: " .. root_tree:position() .. " child " .. child_tree:position())

--child_tree.parent();
child_tree:skip(3)
print("old position root: " .. root_tree:position() .. " child " .. child_tree:position())
root_tree:skip(4)
print("old position root: " .. root_tree:position() .. " child " .. child_tree:position())
child_tree:skip(3)
print("old position root: " .. root_tree:position() .. " child " .. child_tree:position())
