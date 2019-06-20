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

local FieldInfoClass = require("wirebaitlib.dissector.FieldInfo");

local FieldClass = {};

--TODO: enforce the fact that a field must be defined before Taps or Dissectors get called
--[[
    //Constructor
    <Field> FieldClass.new(<string> fieldname)

    example of fieldname = "ip.src"
]]
function FieldClass.new(fieldname)
    local field = {
        m_field_info  = nil;
        name          = fieldname;
        display       = nil;
        type          = nil;
    };

    ---------------------------------------------- initialization ------------------------------------------------------

    for _, v in pairs(__wirebait_state.proto.fields) do
        if v.m_abbr == fieldname then
            field.m_field_info = FieldInfoClass.new(v);
            field.name         = v.m_abbr;
            field.display      = v.m_name;
            field.type         = v.m_type;
        end
    end
    if not field.m_field_info then
        error("The dissector has no defined field '" .. field_path .. "' the field extractor could find!");
    end

    ------------------------------------------------ metamethods -------------------------------------------------------

    function field:__tostring()
        return self.name;
    end

    --TODO: enforce the fact that fields cannot be used outside of dissector or tap
    function field:__call()
        return self.m_field_info;
    end

    setmetatable(field, field)

    return field;
end

--[[TODO: we need a Field.List() (which might not be defined in this library) as described here:fieldname
--https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Field.html#lua_class_Field
--c.f. item  11.2.1.2. Field.list()
]]

return FieldClass;