
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

-- # wirebait dissector
local function createWirebaitDissector()
    local wirebait_dissector = {

    }

    local public_wb_dissector = {
        __is_wirebait_struct = true, --all wirebait data should have this flag so as to know their type
        __wirebait_type_name = "WirebaitDissector",

    }

    return public_wb_dissector;
end

-- # Wirebait Field
local function newWirebaitField(filter, name, size, ws_field)
    --TODO: checks
    --checks('string', 'string', 'number', 'userdata')
    local wb_field = {
        m_filter = filter,
        m_name = name,
        m_size = size,
        m_wireshark_field = ws_field;
    }

    local getFilter = function()
        return wb_field.m_filter;
    end

    local getName = function()
        return wb_field.m_name;
    end

    local getSize = function()
        return wb_field.m_size
    end

    local getWiresharkProtofield = function()
        return wb_field.m_wireshark_field;
    end

    return {
        filter = getFilter,
        name = getName,
        size = getSize,
        wsProtofield = getWiresharkProtofield
    };
end



-- # Wirebait Tree
local function newWirebaitTree(wb_fields_map, ws_tree, buffer, position, size, parent_wb_tree)
    local wirebait_tree = {
        m_wb_fields_map = wb_fields_map; --reference to wirebait.created_protofields to keep track of new fields and register them
        m_ws_tree = ws_tree;
        m_buffer = buffer;
        m_start_position = position or 0;
        m_position = (position or 0) + (size or 0);
        m_end_position = (position or 0) + buffer:len();
        m_parent = parent_wb_tree;
        m_is_root = not parent_wb_tree;
    }

    local getParent = function()
        return wirebait_tree.m_parent;
    end

    local getWiresharkTree = function ()
        return wirebait_tree.m_ws_tree;
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

    local autoFitHighlight = function(self, is_recursive, position) --makes highlighting fit the data that was added or skipped in the tree
        position =  position or self:position();
        assert(position >= wirebait_tree.m_start_position, "Current position is before start position!");
        length = position - wirebait_tree.m_start_position
        wirebait_tree.m_ws_tree:set_len(length);
        if is_recursive and not wirebait_tree.m_is_root then
            self:parent():autoFitHighlight(is_recursive, position);
        end

    end

    local addTree = function (self, filter, name, type_key, size, b, display_map)
        b = b or base.DEC;
        field_key = "f_"..name:gsub('%W','') --Removes all non alpha-num chars from name and prepend 'f_'. For instance "2 Packets" becomes "f_2Packets"

        if not wirebait_tree.m_wb_fields_map[field_key] then --adding new wb protofield if it doesn't exist
            wirebait_tree.m_wb_fields_map[field_key] = wirebait.field.new(filter, name, size, Protofield[type_key](filter, name, b, display_val_map));
        end
        wb_proto_field = wirebait_tree.m_wb_fields_map[field_key];

        --creating a new wireshart tree item and using it to create a new wb tree
        new_ws_tree = wirebait_tree.m_ws_tree:add(wb_proto_field.wsProtofield(), wirebait_tree.m_buffer(wirebait_tree.m_position, wb_proto_field.size()));
        --start_position = wirebait_tree.m_position;
        --wirebait_tree.m_position = wirebait_tree.m_position + size;
        return newWirebaitTree(wirebait_tree.m_wb_fields_map, new_ws_tree, wirebait_tree.m_buffer, wirebait_tree.m_position, size, self)
    end
    
    local addUint8 = function (self, filter, name, base, display_val_map) --display_val_map translated raw value on the wire into display value
        size = 1;
        value = wirebait_tree.m_buffer(wirebait_tree.m_position, size):le_uint();
        return addTree(self, filter, name, "uint8", size, base, display_val_map), value;
    end
    
    local addUint16 = function (self, filter, name, base, display_val_map) --display_val_map translated raw value on the wire into display value
        size = 2;
        value = wirebait_tree.m_buffer(wirebait_tree.m_position, size):le_uint();
        return addTree(self, filter, name, "uint16", size, base, display_val_map), value;
    end
    
    local addUint32 = function (self, filter, name, base, display_val_map) --display_val_map translated raw value on the wire into display value
        size = 4;
        value = wirebait_tree.m_buffer(wirebait_tree.m_position, size):le_uint();
        return addTree(self, filter, name, "uint32", size, base, display_val_map), value;
    end
    
    local addUint64 = function (self, filter, name, base, display_val_map) --display_val_map translated raw value on the wire into display value
        size = 8;
        value = wirebait_tree.m_buffer(wirebait_tree.m_position, size):le_uint64();
        return addTree(self, filter, name, "uint64", size, base, display_val_map), value;
    end
    
    local addString = function (self, filter, name, size, base, display_val_map) --display_val_map translated raw value on the wire into display value
        size = size or 1; -- using 1 if size of string is not provided
        value = wirebait_tree.m_buffer(wirebait_tree.m_position, size):string();
        return addTree(self, filter, name, "string", size, base, display_val_map), value;
    end

    local public_wirebait_tree_interface = {
        __is_wirebait_struct = true, --all wirebait data should have this flag so as to know their type
        __wirebait_type_name = "WirebaitTree",
        __buffer = getBuffer,
        parent = getParent,
        wiresharkTree = getWiresharkTree,
        position = getPosition,
        skip = skip,
        autoFitHighlight = autoFitHighlight,
        addUint8 = addUint8,
        addUint16 = addUint16,
        addUint32 = addUint32,
        addUint64 = addUint64,
        addString = addString
    }

    return public_wirebait_tree_interface;
end





--[[ Using a function to create the wirebait module so that it can have 
private state data ( 1 dissector per wirebait, and wirebait keeps track of protofields
so as to register them automatically)
]]--
local function encapsulatedWirebait() 
    local wirebait = { --wirebait state data which needs to be private
        m_created_proto_fields = {};
        m_size = 0,
        m_dissector = nil
    }

    function wirebait.createProtofield(filter, name, size, ws_protofield)
        new_pf = newWirebaitField(filter, name, size, ws_protofield)
        wirebait.m_created_proto_fields[wirebait.m_size] = new_pf
        wirebait.m_size = wirebait.m_size + 1;
        return new_pf
    end

    function wirebait.createTreeitem(arg1, arg2, ...)
        if arg1.__is_wirebait_struct then
            parent_wirebait_tree = arg1;
            assert(arg2, "Missing proto field to create new treeitem!")
            proto_field = arg2; --//proto field for new subtree;
            ws_tree_item = parent_wirebait_tree:wiresharkTree():add(proto_field);
            wirebait.field.new(proto_field);
            return newWirebaitTree(ws_tree_item or parent_wirebait_tree.wiresharkTree(), parent_wirebait_tree.__buffer(), parent_wirebait_tree.position(), parent_wirebait_tree)
        else
            return newWirebaitTree(wirebait.m_created_proto_fields, arg1, arg2, unpack({...}));
        end
    end

    function wirebait.createDissectorSingleton(name, abbrev_name)
        --checks('string', 'string');
        if not wirebait.m_dissector then
            wirebait.m_dissector = Proto(abbrev_name, name);
        else
            return wirebait.m_dissector;
        end
    end

    function getCreatedProtofieldCount()
        return wirebait.m_size;
    end

    return { --All functions available in wirebait package are named here
        field = { new = wirebait.createProtofield, count = getCreatedProtofieldCount },
        tree = { new = wirebait.createTreeitem },
        dissector = { newSingleton = wirebait.createDissectorSingleton }
    }
end



wirebait = encapsulatedWirebait() 

return wirebait

