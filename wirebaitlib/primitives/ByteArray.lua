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
    ByteArrayClass is meant to provide the functionality of the ByteArray type described in the Wireshark lua API
    documentation.
    [c.f. Wireshark ByteArray](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_ByteArray)

    To instantiate a Wirebait ByteArray, one needs to provide a string representing hexadecimal data. For instance:
    local array = ByteArray.new("AB 0E 14");

    //Constructor
    <ByteArrayClass> ByteArrayClass.new(<string> data_as_hex_string)
]]
local ByteArrayClass = {};

--TODO: add separator as argument, for now the hex string is assumed to have bytes separated by a single white spaces
function ByteArrayClass.new(data_as_hex_string)
    assert(type(data_as_hex_string) == 'string', "Tvb should be based on an hexadecimal string!")
    data_as_hex_string = data_as_hex_string:gsub("%s+","") --removing white spaces
    assert(not data_as_hex_string:find('%X'), "String should be hexadecimal!")
    assert(string.len(data_as_hex_string) % 2 == 0, "String has its last byte cut in half!")

    local byte_array = {
        _struct_type = "ByteArray",
        m_data_as_hex_str = data_as_hex_string:upper()
    }

    ------------------------------------------------ metamethods -------------------------------------------------------

    function byte_array.__concat(byte_array1, byte_array2)
        if type(byte_array1) == 'string' or type(byte_array2) == 'string' then
          return tostring(byte_array1) .. tostring(byte_array2);
        end
        return ByteArrayClass.new(byte_array1.m_data_as_hex_str .. byte_array2.m_data_as_hex_str);
    end

    function byte_array.__eq(byte_array1, byte_array2)
        return (byte_array1.m_data_as_hex_str == byte_array2.m_data_as_hex_str);
    end

    function byte_array:__tostring()
        return self.m_data_as_hex_str;
    end

    function byte_array:__call(start, length)
        return self:subset(start, length)
    end

    ----------------------------------------------- public methods -----------------------------------------------------

    function byte_array:prepend(other_byte_array)
        self.m_data_as_hex_str = other_byte_array.m_data_as_hex_str .. self.m_data_as_hex_str;
    end

    function byte_array:append(other_byte_array)
        self.m_data_as_hex_str =  self.m_data_as_hex_str .. other_byte_array.m_data_as_hex_str;
    end

    function byte_array:set_size(new_num_bytes)
        assert(new_num_bytes >= 0, "New size must be positive!");
        if (new_num_bytes < self:len()) then --truncates the byte array
            self.m_data_as_hex_str = self.m_data_as_hex_str:sub(0, 2*new_num_bytes)
        else --right padding with zeros
            self.m_data_as_hex_str = string.format("%-" .. 2*new_num_bytes .."s", self.m_data_as_hex_str):gsub(' ','0')
        end
    end

    function byte_array:get_index(index)
        return tonumber(self.m_data_as_hex_str:sub(2*index+1, 2*index + 2), 16);
    end

    function byte_array:set_index(index, value)
        --TODO: implement this method
        assert("false", "ByteArray:set_index() is not available yet!")
    end

    function byte_array:len()
        return math.floor(self.m_data_as_hex_str:len() / 2);
    end

    --TODO: in wireshark, this method expects 2 arguments
    function byte_array:toHex()
        return self.m_data_as_hex_str;
    end

    function byte_array:subset(start, length)
        assert(start and start >= 0,         "Start position should be positive positive!");
        assert(length and length >= 0,       "Length should be positive!");
        assert(start + length <= self:len(), "Index get out of bounds!")
        local sub_data_as_hex_str = self.m_data_as_hex_str:sub(2*start+1, 2*(start + length));
        return ByteArrayClass.new(sub_data_as_hex_str);
    end

    function byte_array:tvb()
        local TvbClass = require("wirebaitlib.packet_data.Tvb");
        return TvbClass.new(self); --TODO: modify tvb to be constructed from a byte array!
    end

    --------------------------------- public methods (not part of Wireshark Lua API) -----------------------------------

    --TODO: add unit test for this method
    function byte_array:toUInt32()
        assert(self:len() <= 4, "cannot call ByteArray:toUInt32() when ByteArray:len() > 4");
        --left pad with zeros to make 4 bytes
        local hex_str = string.format("%016s",self.m_data_as_hex_str):gsub(" ","0");
        return tonumber(hex_str, 16);
    end

    --TODO: add unit test for this method
    function byte_array:swapByteOrder()
        assert(self:len() <= 8, "It does not make sense to swap byte order on more than 8 bytes at a time")
        local new_hex_str = "";
        for i=1,#self.m_data_as_hex_str/2 do
            new_hex_str = self.m_data_as_hex_str:sub(2*i-1,2*i) .. new_hex_str;
        end
        return ByteArrayClass.new(new_hex_str);
    end

    setmetatable(byte_array, byte_array);
    return byte_array;
end

return ByteArrayClass;