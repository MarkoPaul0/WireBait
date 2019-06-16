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

local bw     = require("wirebaitlib.primitives.Bitwise");
local UInt64 = require("wirebaitlib.primitives.UInt64");

--[[
    ProtoFieldClass is meant to provide the functionality of the ProtoField type described in the Wireshark lua API
    documentation.
    [c.f. Wireshark Proto](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField)
]]
local ProtoFieldClass = { base = {NONE=0, DEC=1, HEX=2, OCT=3, DEC_HEX=4, HEX_DEC=5}}
--ProtoField.base --[[c.f. [Wireshark Repo](https://github.com/wireshark/wireshark/blob/537705a8b20ee89bf1f713bc0c9959cf21b26900/test/lua/globals_2.2.txt) ]]

function ProtoFieldClass.new(name, abbr, ftype, value_string, fbase, mask, desc)
    assert(name and abbr and ftype, "ProtoField name, abbr, and type must not be nil!");
    assert(type(name) == "string" and type(abbr) == "string" and type(ftype) == "string", "ProtoField name, abbr, and type must be strings!");
    assert(not fbase or type(fbase) == "number" and fbase == math.floor(fbase), "The optional ProtoField base must to be an integer!");
    assert(not mask or type(mask) == "number" and mask == math.floor(mask), "The optional ProtoField mask must to be an integer!");
    assert(not value_string or type(value_string) == "table", "The optional ProtoField valuestring must be a table!");
    local protofield = {
        _struct_type   = "ProtoField";
        m_name         = name; --e.g. "Number of Messages"
        m_abbr         = abbr; --e.g. "proto.num_msg"
        m_type         = ftype;
        m_value_string = value_string; --[[table of values and their corresponding string value ]]
        m_base         = fbase; --[[determines what base is used to display an treeitem value]]
        m_mask         = mask; --[[mask only works for types that are by definition <= 8 bytes]]
        m_description  = desc; --[[The description is a text displayed in the Wireshark GUI when the field is selected. Irrelevant in wirebait]]
        m_last_buffer  = nil; --TODO: this is not good enough as values will be persisted accross packets
    }

    function protofield:getValueFromBuffer(buffer)
        local mask = protofield.m_mask;
        local extractValueFuncByType = {
            FT_NONE     = function (buf) return "" end,
            FT_BOOLEAN  = function (buf) return buf:uint64() > 0 end,
            FT_UINT8    = function (buf) return bw.And(buf:uint(), (mask or 0xFF)) end,
            FT_UINT16   = function (buf) return bw.And(buf:uint(), (mask or 0xFFFF)) end,
            FT_UINT24   = function (buf) return bw.And(buf:uint(), (mask or 0xFFFFFF)) end,
            FT_UINT32   = function (buf) return bw.And(buf:uint(), (mask or 0xFFFFFFFF)) end,
            FT_UINT64   = function (buf) return buf:uint64():band(mask or UInt64.max()) end,
            FT_INT8     = function (buf) return buf:int(mask) end, --[[mask is provided here because it needs to be applied on the raw value and not on the decoded int]]
            FT_INT16    = function (buf) return buf:int(mask) end,
            FT_INT24    = function (buf) return buf:int(mask) end,
            FT_INT32    = function (buf) return buf:int(mask) end,
            FT_INT64    = function (buf) return buf:int64(mask) end,
            FT_FLOAT    = function (buf) return buf:float() end,
            FT_DOUBLE   = function (buf) return buf:float() end,
            FT_STRING   = function (buf) return buf:string() end,
            FT_STRINGZ  = function (buf) return buf:stringz() end,
            FT_ETHER    = function (buf) return buf:eth() end,
            FT_BYTES    = function (buf) return buf:__tostring(); end,
            FT_IPv4     = function (buf) return buf:ipv4() end,
            FT_GUID     = function (buf) return buf:guid() end
        };
        self.m_last_buffer = buffer;
        local func = extractValueFuncByType[self.m_type];
        assert(func, "Unknown protofield type '" .. self.m_type .. "'!")
        return func(buffer);
    end

    --[[If the protofield has a mask, the mask is applied to the buffer and the value is printed as bits.
    For instance a mask of 10010001 applied to a buffer of 11101111 will give the result "1..0...1"]]
    function protofield:getMaskPrefix(buffer)
        assert(buffer:len() > 0, "buffer is empty!");
        if not self.m_mask then
            return "";
        end
        local value = self:getValueFromBuffer(buffer);
        local str_value = tostring(value);
        local current_bit = bw.Lshift(1, buffer:len()*8 - 1);
        local displayed_masked_value = "";
        while current_bit > 0 do
            if bw.And(self.m_mask, current_bit) == 0 then
                displayed_masked_value = displayed_masked_value .. ".";
            else
                if bw.And(value, current_bit) > 0 then
                    displayed_masked_value = displayed_masked_value .. "1";
                else
                    displayed_masked_value = displayed_masked_value .. "0";
                end
            end
            current_bit = bw.Rshift(current_bit, 1);
        end
        displayed_masked_value = string.format("%".. buffer:len()*8 .."s", displayed_masked_value):gsub(" ",".");
        displayed_masked_value = displayed_masked_value:gsub("....", "%1 "):sub(1, -2);
        str_value = displayed_masked_value .. " = ";
        return str_value;
    end
    
    --[[ Turns ..11...0..1...10 into 110110 and get its int value]]
    local function getValueFromAggregatedMaskedBits(masked_value, mask)
        local result = 0;
        local shift = 0;
        local current_bit = 1
        while current_bit <= masked_value do
            if bw.And(masked_value, current_bit) > 0 then
                result = result + bw.Lshift(1, shift);
                shift = shift + 1;
            elseif bw.And(mask, current_bit) > 0 then
                shift = shift + 1;
            end
            current_bit = bw.Lshift(current_bit, 1);
        end
        return result;
    end

    function protofield:getDisplayValueFromBuffer(buffer)
        local value = self:getValueFromBuffer(buffer);
        if self.m_mask then
            value = getValueFromAggregatedMaskedBits(value, self.m_mask);
        end
        local str_value = tostring(value);
        local value_string = nil;
        self.m_last_buffer = buffer;
        if self.m_value_string and self.m_value_string[value] then
            value_string = self.m_value_string[value];
        end
        if self.m_base == ProtoFieldClass.base.HEX then
            if value_string then
                str_value = value_string .. " (0x" .. buffer:bytes() .. ")";
            else
                str_value = "0x" .. buffer:bytes();
            end
        elseif self.m_base == ProtoFieldClass.base.HEX_DEC then
            if value_string then
                str_value =  value_string .. " (0x" .. buffer:bytes() .. ")";
            else
                str_value = "0x" .. buffer:bytes() .. " (" .. str_value .. ")";
            end
        elseif self.m_base == ProtoFieldClass.base.DEC_HEX then
            if value_string then
                str_value =  value_string .. " (" .. value .. ")";
            else
                str_value =  str_value .. " (0x" .. buffer:bytes() .. ")";
            end
        else --treat any other base or no base set as base.DEC
            if value_string then
                str_value =  value_string .. " (" .. value .. ")";
            end
        end
        return str_value;
    end

    return protofield;
end

local ftypes = {  --[[c.f. [wireshark protield types](https://github.com/wireshark/wireshark/blob/695fbb9be0122e280755c11b9e0b89e9e256875b/epan/wslua/wslua_proto_field.c) ]]
    NONE      = "FT_NONE",
    BOOLEAN   = "FT_BOOLEAN",
    UINT8     = "FT_UINT8",
    UINT16    = "FT_UINT16",
    UINT24    = "FT_UINT24",
    UINT32    = "FT_UINT32",
    UINT64    = "FT_UINT64",
    INT8      = "FT_INT8",
    INT16     = "FT_INT16",
    INT24     = "FT_INT24",
    INT32     = "FT_INT32",
    INT64     = "FT_INT64",
    FLOAT     = "FT_FLOAT",
    DOUBLE    = "FT_DOUBLE",
    STRING    = "FT_STRING",
    STRINGZ   = "FT_STRINGZ",
    ETHER     = "FT_ETHER",
    BYTES     = "FT_BYTES",
    IPv4      = "FT_IPv4",
    GUID      = "FT_GUID"
}

ProtoFieldClass.ftypes = ftypes;

function ProtoFieldClass.none(abbr, name, desc)                       return ProtoFieldClass.new(name, abbr, ftypes.NONE,    nil, nil, nil, desc) end
function ProtoFieldClass.bool(abbr, name, fbase, value_string, ...)   return ProtoFieldClass.new(name, abbr, ftypes.BOOLEAN, value_string, fbase, ...) end
function ProtoFieldClass.uint8(abbr, name, fbase, value_string, ...)  return ProtoFieldClass.new(name, abbr, ftypes.UINT8,   value_string, fbase, ...) end
function ProtoFieldClass.uint16(abbr, name, fbase, value_string, ...) return ProtoFieldClass.new(name, abbr, ftypes.UINT16,  value_string, fbase, ...) end
function ProtoFieldClass.uint24(abbr, name, fbase, value_string, ...) return ProtoFieldClass.new(name, abbr, ftypes.UINT24,  value_string, fbase, ...) end
function ProtoFieldClass.uint32(abbr, name, fbase, value_string, ...) return ProtoFieldClass.new(name, abbr, ftypes.UINT32,  value_string, fbase, ...) end
function ProtoFieldClass.uint64(abbr, name, fbase, value_string, ...) return ProtoFieldClass.new(name, abbr, ftypes.UINT64,  value_string, fbase, ...) end
function ProtoFieldClass.int8(abbr, name, fbase, value_string, ...)   return ProtoFieldClass.new(name, abbr, ftypes.INT8,    value_string, fbase, ...) end
function ProtoFieldClass.int16(abbr, name, fbase, value_string, ...)  return ProtoFieldClass.new(name, abbr, ftypes.INT16,   value_string, fbase, ...) end
function ProtoFieldClass.int24(abbr, name, fbase, value_string, ...)  return ProtoFieldClass.new(name, abbr, ftypes.INT24,   value_string, fbase, ...) end
function ProtoFieldClass.int32(abbr, name, fbase, value_string, ...)  return ProtoFieldClass.new(name, abbr, ftypes.INT32,   value_string, fbase, ...) end
function ProtoFieldClass.int64(abbr, name, fbase, value_string, ...)  return ProtoFieldClass.new(name, abbr, ftypes.INT64,   value_string, fbase, ...) end
function ProtoFieldClass.float(abbr, name, value_string, desc)        return ProtoFieldClass.new(name, abbr, ftypes.FLOAT,   value_string, nil, nil, desc) end
function ProtoFieldClass.double(abbr, name, value_string, desc)       return ProtoFieldClass.new(name, abbr, ftypes.DOUBLE,  value_string, nil, nil, desc) end
function ProtoFieldClass.string(abbr, name, display, desc)            return ProtoFieldClass.new(name, abbr, ftypes.STRING,  nil, display, nil, desc) end
function ProtoFieldClass.stringz(abbr, name, display, desc)           return ProtoFieldClass.new(name, abbr, ftypes.STRINGZ, nil, display, nil, desc) end
function ProtoFieldClass.ether(abbr, name, desc)                      return ProtoFieldClass.new(name, abbr, ftypes.ETHER,   nil, nil, nil, desc) end
function ProtoFieldClass.bytes(abbr, name, fbase, desc)               return ProtoFieldClass.new(name, abbr, ftypes.BYTES,   nil, fbase, nil, desc) end
function ProtoFieldClass.ipv4(abbr, name, desc)                       return ProtoFieldClass.new(name, abbr, ftypes.IPv4,    nil, nil, nil, desc) end
function ProtoFieldClass.guid(abbr, name, desc)                       return ProtoFieldClass.new(name, abbr, ftypes.GUID,    nil, nil, nil, desc) end

return ProtoFieldClass;