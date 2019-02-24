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

local Utils         = require("wirebaitlib.primitives.Utils");
local TvbRangeClass = require("wirebaitlib.packet_data.TvbRange");

--[[
    TvbClass is meant to provide the functionality of the Tvb type described in the Wireshark lua API
    documentation.
    [c.f. Wireshark Tvb](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb)

    To instantiate a Wirebait TvbClass, one needs to provide a ByteArray containing the underlying packet data.
]]
local TvbClass = {};

function TvbClass.new(byte_array, offset)
    assert(Utils.typeof(byte_array) == 'ByteArray', "Tvb constructor needs a ByteArray!")
    local tvb = {
        _struct_type = "Tvb",
        m_byte_array = byte_array,
        m_offset     = offset or 0;
    }

    ------------------------------------------------ metamethods -------------------------------------------------------

    -- Metamethod allowing for a call like `range = tvb(1,2);` to be equivalent to `range = tvb:range(1,2);`
    function tvb:__call(start, length)
        return self:range(start, length);
    end

    function tvb:__tostring()
        if self:len() > 24 then --[[ellipsis after 24 bytes c.f. [tvbrange:__tostring()](https://wiki.wireshark.org/LuaAPI/Tvb#tvbrange:__tostring.28.29) ]]
            return tostring(self.m_byte_array):sub(0,48) .. "...";
        end
        return  string.lower(tostring(self.m_byte_array));
    end

    ----------------------------------------------- public methods -----------------------------------------------------

    function tvb:len()
        return self.m_byte_array:len();
    end

    --TODO: work on this method
    function tvb:reported_len()
        assert(false, "Tvb:reported_len() is not available yet");
    end

    --TODO: work on this!
    function tvb:reported_length_remaining()
        --assert(false, "Tvb:reported_length_remaining() is not available yet");
        return tvb:len();
    end

    function tvb:bytes()
        return self.m_byte_array;
    end

    function tvb:offset()
        return self.m_offset;
    end

    function tvb:range(start, length)
        assert(start and start >= 0, "Start position should be positive positive!");
        length = length or self:len() - start; --add unit test for the case where no length was provided
        assert(length >= 0, "Length should be positive!");
        assert(start + length <= self:len(), "Index get out of bounds!")
        return TvbRangeClass.new(self.m_byte_array:subset(start, length), start + self.m_offset)
    end

    setmetatable(tvb, tvb)
    return tvb;
end

return TvbClass;