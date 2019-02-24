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

--[[
    ProtoClass is meant to provide the functionality of the Proto type described in the Wireshark lua API
    documentation.
    [c.f. Wireshark Proto](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_Proto)

    //Constructor
    <ProtoClass> ProtoClass.new(<string> abbr, <string> description)
]]
local ProtoClass = {}

function ProtoClass.new(abbr, description)
    assert(description and abbr, "Proto argument should not be nil!");
    local proto = {
        _struct_type = "Proto";
        m_description = description,
        m_abbr = abbr,
        fields = {}, --protofields
        dissector = {}, --dissection function
        name = description --ws api
    }

    assert(__wirebait_state.proto == nil, "Wirebait currenlty only support 1 proto per dissector file!");
    __wirebait_state.proto = proto;
    return proto;
end

return ProtoClass;