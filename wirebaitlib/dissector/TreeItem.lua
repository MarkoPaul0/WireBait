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



local utils = require("wirebaitlib.primitives.utils");

local TreeItem = {};

function TreeItem.new(protofield, buffer, parent)
    --assert(utils.typeof(protofield) == "ProtoField", "Expected ProtoField but got " .. utils.typeof(protofield));
    --assert(utils.typeof(buffer) == "Tvb", "Expected Tvb");
    --assert(not parent or utils.typeof(parent) == "TreeItem", "Expected TreeItem");
    local tree_item = {
        _struct_type = "TreeItem",
        m_protofield = protofield,
        m_depth      = parent and parent.m_depth + 1 or 0,
        m_tvb        = buffer, --TODO: assert type is tvb, --TODO: this is not used
        m_text       = nil
    }

    local function prefix(depth)
        assert(depth >= 0, "Tree depth cannot be negative (" .. depth .. ")!");
        return depth == 0 and "" or string.rep(" ", 3*(depth - 1)) .. "└─ ";
    end

    --[[ Private function adding a proto to the provided treeitem ]]
    local function addProto(tree, proto, buffer_or_value, texts)
        assert(buffer_or_value, "When adding a protofield, either a tvb range, or a value must be provided!");
        if type(buffer_or_value) == "string" or type(buffer_or_value) == "number" then
            --[[if no buffer provided, value will be appended to the treeitem, and no bytes will be highlighted]]
            value = buffer_or_value;
        elseif utils.typeof(buffer_or_value) == "TvbRange" then
            --[[if buffer is provided, value maybe provided, in which case it will override the value parsed from the buffer]]
            buffer = buffer_or_value
            --assert(buffer._struct_type == "Tvb", "Buffer expected but got another userdata type!")
            if #texts > 0 then
                value = texts[1] --might be nil
                table.remove(texts,1); --removing value from the texts array
            end
            if #texts == 0 then
                texts = nil
            end
        else
            error("buffer_or_value cannot be of type " .. utils.typeof(buffer_or_value));
        end
        assert(buffer or value, "Bug in this function, buffer and value cannot be both nil!");

        local child_tree = TreeItem.new(protofield, buffer, tree);
        if texts then --texts override the value displayed in the tree including the header defined in the protofield
            child_tree.m_text = tostring(prefix(tree.m_depth) .. table.concat(texts, " "));
        else
            child_tree.m_text = tostring(prefix(tree.m_depth) .. proto.m_description);
        end
        return child_tree;
    end

    --[[ Private function adding a protofield to the provided TreeItem ]]
    local function addProtoField(tree, protofield, buffer_or_value, texts)
        assert(buffer_or_value, "When adding a protofield, either a tvb range, or a value must be provided!");
        local value = nil;
        if type(buffer_or_value) == "string" or type(buffer_or_value) == "number" then
            --[[if no buffer provided, value will be appended to the TreeItem, and no bytes will be highlighted]]
            value = buffer_or_value;
        else
            --[[if buffer is provided, value maybe provided, in which case it will override the value parsed from the buffer]]
            buffer = buffer_or_value
            assert(buffer._struct_type == "TvbRange", "Buffer expected but got another userdata type!")
            if texts then
                if type(texts) == "table" then
                    if #texts > 0 then
                        value = texts[1] --might be nil
                        table.remove(texts,1); --removing value from the texts array
                    end
                    if #texts == 0 then
                        texts = nil;
                    end
                else
                    value = texts;
                    texts = nil;
                end
            end
        end
        assert(buffer or value, "Bug in this function, buffer and value cannot be both nil!");

        local child_tree = TreeItem.new(protofield, buffer, tree);
        if texts then --texts override the value displayed in the tree including the header defined in the protofield
            child_tree.m_text = tostring(prefix(tree.m_depth) .. table.concat(texts, " "));
        else
            local printed_value = tostring(value or protofield:getDisplayValueFromBuffer(buffer)) -- buffer(0, size):bytes()
            child_tree.m_text = tostring(prefix(tree.m_depth) .. protofield:getMaskPrefix(buffer) .. protofield.m_name .. ": " .. printed_value); --TODO review the or buffer:len
        end
        return child_tree;
    end

    --[[ Private function adding a TreeItem to the provided TreeItem, without an associated protofield ]]
    --[[ Very (like VERY) lazy, and hacky, and poor logic but it works ]]
    -- TODO: clean this up!
    local function addTreeItem(tree, buffer, value, texts)
        local protofield = nil;
        table.insert(texts, 1, value); --insert value in first position
        table.insert(texts, 1, "");
        return addProtoField(tree, protofield, buffer, texts)
    end

    --[[ Checks if a protofield was registered]]
    local function checkProtofieldRegistered(protofield)
        for k, v in pairs(__wirebait_state.proto.fields) do
            if protofield == v then
                return true;
            end
        end
        return false;
    end

    --[[TODO: add uni tests]]
    function tree_item:add(arg1, arg2, arg3, ...)
        assert(arg1 and arg2, "treeitem:add() requires at least 2 arguments!");

        local new_treeitem = nil;
        if utils.typeof(proto_or_protofield_or_buffer) == "Proto" then
            if not checkProtofieldRegistered(arg1) then
                io.write("ERROR: Protofield '" .. proto_or_protofield_or_buffer.m_name .. "' was not registered!")
            end
            new_treeitem = addProto(self, arg1, arg2, {arg3, ...});
        elseif utils.typeof(proto_or_protofield_or_buffer) == "ProtoField" then
            new_treeitem = addProtoField(self, arg1, arg2, {arg3, ...});
        elseif utils.typeof(proto_or_protofield_or_buffer) == "TvbRange" then --adding a tree item without protofield
            local texts = {arg3, ...};
            table.insert(texts, 1, arg2); --insert value in first position
            table.insert(texts, 1, "");
            new_treeitem = addProtoField(self, nil, arg1, texts);
        else
            error("First argument in treeitem:add() should be a Proto or Profofield");
        end

        table.insert(__wirebait_state.packet_info.treeitems_array, new_treeitem);
        return new_treeitem;
    end


    function tree_item:add(proto_or_protofield_or_buffer, buffer, value, ...)
        assert(proto_or_protofield_or_buffer and buffer, "treeitem:add() requires at least 2 arguments!");
        if utils.typeof(proto_or_protofield_or_buffer) == "ProtoField" and not checkProtofieldRegistered(proto_or_protofield_or_buffer) then
            io.write("ERROR: Protofield '" .. proto_or_protofield_or_buffer.m_name .. "' was not registered!")
        end
        local new_treeitem = nil;
        if utils.typeof(proto_or_protofield_or_buffer) == "Proto" then
            new_treeitem = addProto(self, proto_or_protofield_or_buffer, buffer, {value, ...});
        elseif utils.typeof(proto_or_protofield_or_buffer) == "ProtoField" then
            new_treeitem = addProtoField(self, proto_or_protofield_or_buffer, buffer, {value, ...});
        elseif utils.typeof(proto_or_protofield_or_buffer) == "TvbRange" then --adding a tree item without protofield
            new_treeitem = addTreeItem(self, proto_or_protofield_or_buffer, buffer, {value, ...});
        else
            error("First argument in treeitem:add() should be a Proto or Profofield");
        end
        table.insert(__wirebait_state.packet_info.treeitems_array, new_treeitem);
        return new_treeitem;
    end

    --[[TODO: add unit tests]]
    function tree_item:add_le(proto_or_protofield_or_buffer, buffer, value, ...)
        assert(utils.typeof(proto_or_protofield_or_buffer) == "TvbRange" or utils.typeof(buffer) == "TvbRange", "Expecting a tvbrange somewhere in the arguments list!")
        if utils.typeof(proto_or_protofield_or_buffer) == "TvbRange" then
            proto_or_protofield_or_buffer = buffer.new(proto_or_protofield_or_buffer:swapped_bytes());
        else
            buffer = buffer.new(buffer:swapped_bytes());
        end
        return self:add(proto_or_protofield_or_buffer, buffer, value, ...)
    end

    function tree_item:set_text(text)
        text:gsub("\n", " ");
        self.m_text = text
    end

    function tree_item:append_text(text)
        text:gsub("\n", " ");
        self.m_text = self.m_text .. text
    end

    function tree_item:set_len(length)
        io.write("WIREBAIT WARNING: TreeItem:set_length() is not supported by wirebait yet.");
    end

    function tree_item:set_generated()
        io.write("WIREBAIT WARNING: TreeItem:set_generated() is not supported by wirebait yet.");
    end

    function tree_item:set_hidden()
        io.write("WIREBAIT WARNING: TreeItem:set_hidden() is not supported by wirebait yet.");
    end

    function tree_item:set_expert_flags()
        io.write("WIREBAIT WARNING: TreeItem:set_expert_flags() is not supported by wirebait yet.");
    end

    function tree_item:set_expert_info()
        io.write("WIREBAIT WARNING: TreeItem:set_expert_info() is not supported by wirebait yet.");
    end

    return tree_item;
end

return TreeItem;