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

local utils    = require("wirebaitlib.primitives.Utils");
local TvbRange = require("wirebaitlib.packet_data.TvbRange");

local Tvb = {};

function Tvb.new(byte_array, offset)
    assert(utils.typeof(byte_array) == 'ByteArray', "Tvb constructor needs a ByteArray!")

    local tvb = {
        _struct_type = "Tvb",
        m_data = byte_array,
        m_offset = offset or 0; --TODO: offset is not used for anything here
    }

    --TODO: work on this method
    function tvb:reported_len()
        assert(false, "tvb:reported_len() is not available yet");
    end

    function tvb:len()
        return self.m_data:len();
    end

    function tvb:reported_length_remaining()
        --TODO: work on this!    
        --TODO: work on this!
        --TODO: work on this!
        --TODO: work on this!
        --TODO: work on this!

        io.write("[WARNING] tvb:reported_length_remaining() is not supported yet and returns len()!");
        return tvb:len();
    end

    function tvb:bytes()
        return self.m_data;
    end

    function tvb:offset()
        return self.m_offset;
    end

    function tvb:range(start, length)
        assert(start and start >= 0, "Start position should be positive positive!");
        length = length or self:len() - start; --add unit test for the case where no length was provided
        assert(length >= 0, "Length should be positive!");
        assert(start + length <= self:len(), "Index get out of bounds!")
        return TvbRange.new(self.m_data:subset(start, length), offset)
    end

    --equivalent to tvb:range() but allows tvb to be called as a function
    function tvb:__call(start, length)
        return self:range(start, length);
    end

    function tvb:__tostring()
        if self:len() > 24 then --[[ellipsis after 24 bytes c.f. [tvbrange:__tostring()](https://wiki.wireshark.org/LuaAPI/Tvb#tvbrange:__tostring.28.29) ]]
            return tostring(self.m_data):sub(0,48) .. "...";
        end
        return  string.lower(tostring(self.m_data));
    end

    setmetatable(tvb, tvb)

    return tvb;
end

return Tvb;