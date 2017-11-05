
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

--dofile("./Wirebait/wireshark_mock.lua")
local wireshark = require("Wirebait.wireshark_mock")

-- # wirebait dissector
local function createWirebaitDissector()
    local wirebait_dissector = {

    }
end



-- # Wirebait Tree
local function newWirebaitTree(wireshark_tree, buffer, position, parent)
    print("WS TREE ITEM is at: " .. tostring(wireshark_tree))
    local wirebait_tree = {
        m_wireshark_tree = wireshark_tree;
        m_buffer = buffer;
        m_start_position = position or 0;
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
        if not wirebait_tree.m_is_root then
            self:parent():skip(byte_count);
        end
        assert(wirebait_tree.m_position + byte_count <= wirebait_tree.m_end_position , "Trying to skip more bytes than available in buffer managed by wirebait tree!")
        wirebait_tree.m_position = wirebait_tree.m_position + byte_count;
    end

    local setLength = function(self, L)
        wirebait_tree.m_wireshark_tree:set_len(L);
    end

    local autoFitHighlight = function(self, is_recursive) --makes highlighting fit the data that was added or skipped in the tree
        position =  self:position();
        --print(position);
        assert(position > wirebait_tree.m_start_position, "Current position is before start position!");
        length = position - wirebait_tree.m_start_position
        --print("Length for " .. tostring(self) .. " is " .. length .. " bytes.");
        setLength(self,length);
        if is_recursive and not wirebait_tree.m_is_root then
            self:parent():autoFitHighlight(is_recursive);
        end

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
        __buffer = getBuffer,
        parent = getParent,
        wiresharkTree = getWiresharkTree,
        position = getPosition,
        length = getLength,
        skip = skip,
        autoFitHighlight = autoFitHighlight
    }

    --print("Public address: " .. tostring(public_interface));
    return public_interface;
end


local function newWirebaitTree_overload(arg1, arg2, ...)
    --for i in pairs(arg1) do print(i) end
    if arg1.__is_wirebait_struct then
        parent_wirebait_tree = arg1;
        assert(arg2, "Missing proto field to create new treeitem!")
        proto_field = arg2; --//proto field for new subtree;
        ws_tree_item = parent_wirebait_tree:wiresharkTree():add(proto_field);
        wirebait.field.new(proto_field);

        return newWirebaitTree(ws_tree_item or parent_wirebait_tree.wiresharkTree(), parent_wirebait_tree.__buffer(), parent_wirebait_tree.position(), parent_wirebait_tree)
    else
        return newWirebaitTree(arg1, arg2, unpack({...}));
    end
end


-- # Wirebait Field
local function newWirebaitField(ws_field)
    local wirebait_field = {
        m_wireshark_field = ws_field;
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
        name = getName,
        size = getSize
    };
end

--All functions available in wirebait package are named here
wirebait = {
    created_proto_fields = {}, --TODO: this is accessible publicly, and it shouldn't
    pf_count = 0, --count of created_proto_fields
    field = {
        new = function (...)
            new_pf = newWirebaitField(unpack({...}))
            wirebait.created_proto_fields[wirebait.pf_count] = new_pf
            --print("Added PROTO FIELD TO COLLECTION!")
            return new_pf
        end
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

ws_root_tree_item = wireshark.treeitem.new();
ws_child_tree_item = wireshark.treeitem.new();
ws_child_tree_item2 = wireshark.treeitem.new();
print("tr " .. tostring(ws_root_tree_item) .. " tr1 " .. tostring(ws_child_tree_item) .. " tr2 " .. tostring(ws_child_tree_item2) )

root_tree = wirebait.tree.new(ws_root_tree_item, buffer, 0);
print("root address " .. tostring(root_tree) .. " parent " .. tostring(root_tree:parent()))

--print("parent of root tree: " .. tostring(root_tree.parent()))

--print("old position " .. root_tree:position())
root_tree:skip(1)

proto_field1  = wireshark.protofield.new("proto_fied1", "test.pf1", {});
child_tree_1 = wirebait.tree.new(root_tree, proto_field1)
--print("child address " .. tostring(child_tree) .. "\n")

print("old position root: " .. root_tree:position() .. " child " .. child_tree_1:position())

--child_tree.parent();
child_tree_1:skip(3)
print("old position root: " .. root_tree:position() .. " child " .. child_tree_1:position())
--root_tree:skip(4)
print("old position root: " .. root_tree:position() .. " child " .. child_tree_1:position())
child_tree_1:skip(3)
print("old position root: " .. root_tree:position() .. " child " .. child_tree_1:position())
child_tree_1:autoFitHighlight(true)

print("Length for root_tree item is " .. tostring(root_tree:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(root_tree:wiresharkTree()));
print("Length for child_tree item is " .. tostring(child_tree_1:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_1:wiresharkTree()));


child_tree_2 = wirebait.tree.new(root_tree, proto_field1)
--print("child address " .. tostring(child_tree) .. "\n")
child_tree_2:skip(11);

print("old position root: " .. root_tree:position() .. " child2 " .. child_tree_2:position())
print("Length for root_tree item is " .. tostring(root_tree:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(root_tree:wiresharkTree()));
print("Length for child_tree item is " .. tostring(child_tree_1:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_1:wiresharkTree()));
print("Length for child_tree2 item is " .. tostring(child_tree_2:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_2:wiresharkTree()));
child_tree_2:autoFitHighlight(false)
print("Length for root_tree item is " .. tostring(root_tree:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(root_tree:wiresharkTree()));
print("Length for child_tree item is " .. tostring(child_tree_1:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_1:wiresharkTree()));
print("Length for child_tree2 item is " .. tostring(child_tree_2:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_2:wiresharkTree()));
child_tree_2:autoFitHighlight(true)
print("Length for root_tree item is " .. tostring(root_tree:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(root_tree:wiresharkTree()));
print("Length for child_tree item is " .. tostring(child_tree_1:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_1:wiresharkTree()));
print("Length for child_tree2 item is " .. tostring(child_tree_2:wiresharkTree().m_length) .. " bytes. tree item is at " .. tostring(child_tree_2:wiresharkTree()));

