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

local FieldExtractor = { FieldInfo = {}, Field = {} };

function FieldExtractor.FieldInfo.new(protofield)
    assert(protofield);
    local field_info = {
        m_protofield = protofield;
    }

    function field_info:__len()
        --print("[WARNING] FieldInfo:__len() is not supported yet! Contact MarkoPaul0, the Wirebait developer.");
        return 0;
    end

    function field_info:__unm()
        error("FieldInfo:__unm() is not supported yet! Contact MarkoPaul0, the Wirebait developer.");
    end

    function field_info:__call()
        return self.m_protofield:getDisplayValueFromBuffer(self.m_protofield.m_last_buffer);
        --error("TODO: FieldInfo:__call()");
    end

    setmetatable(field_info, field_info)
    return field_info;
end

function FieldExtractor.Field.new(field_path) --Field Extractors
    local field = {
        m_info = nil;
        name = nil;
        display = nil;
    };

    for k, v in pairs(state.proto.fields) do
        if v.m_abbr == field_path then
            field.m_info = FieldExtractor.FieldInfo.new(v);
            field.name = v.m_abbr;
            field.display = v.m_name;
            field['type'] = v.m_type;
        end
    end
    if not field.m_info then
        error("The dissector has no defined field '" .. field_path .. "' the field extractor could find!");
    end

    function field:__tostring()
        return self.name;
    end

    function field:__call()
        return self.m_info;
    end

    setmetatable(field, field)
    --table.insert(state.field_extractors, field);
    return field;
end

return FieldExtractor;