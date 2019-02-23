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

local Utils  = require("wirebaitlib.primitives.Utils");
local bw     = require("wirebaitlib.primitives.Bitwise");
local UInt64 = require("wirebaitlib.primitives.UInt64");
local Int64  = require("wirebaitlib.primitives.Int64");

local TvbRangeClass = {};

--[[
    TvbRangeClass is meant to provide the functionality of the TvbRange type described in the Wireshark lua API
    documentation.
    [c.f. Wireshark Tvb](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_TvbRange)

    To instantiate a Wirebait TvbRange, one needs to provide a ByteArray containing the underlying packet data.
]]
function TvbRangeClass.new(byte_array)
    assert(Utils.typeof(byte_array) == 'ByteArray', "TvbRange constructor needs a ByteArray!")

    local tvb_range = {
        _struct_type = "TvbRange",
        m_byte_array = byte_array
    }

    local escape_replacements = {["\0"]="\\0", ["\t"]="\\t", ["\n"]="\\n", ["\r"]="\\r", }

    ------------------------------------------------ metamethods -------------------------------------------------------

    function tvb_range:__call(start, length) --allows TvbRange to be called as a function
        return self:range(start, length);
    end

    function tvb_range:__tostring()
        if self:len() > 24 then --[[ellipsis after 24 bytes c.f. [tvbrange:__tostring()](https://wiki.wireshark.org/LuaAPI/Tvb#tvbrange:__tostring.28.29) ]]
            return string.format("%48s", string.lower(self.m_byte_array.m_data_as_hex_str)) .. "...";
        end
        return  string.lower(self.m_byte_array.m_data_as_hex_str);
    end

    ----------------------------------------------- public methods -----------------------------------------------------

    function tvb_range:len()
        return self.m_byte_array:len();
    end

    function tvb_range:bytes()
        return self.m_byte_array;
    end

    function tvb_range:offset()
        return self.m_offset;
    end

    function tvb_range:tvb()
        --TODO: add unit tests
        local TvbClass = require("wirebaitlib.packet_data.Tvb");
        return TvbClass.new(self.m_byte_array);
    end

    function tvb_range:range(start, length)
        assert(start and start >= 0, "Start position should be positive positive!");
        length = length or self:len() - start; --add unit test for the case where no length was provided
        assert(length >= 0, "Length should be positive!");
        assert(start + length <= self:len(), "Index get out of bounds!")
        return TvbRangeClass.new(self.m_byte_array:subset(start,length));
    end

    ----------------------------------------- big endian uint conversion -----------------------------------------------

    function tvb_range:uint()
        assert(self:len() <= 4, "tvbrange:uint() can only decode bytes! (len = " .. self:len() .. ")");
        return self.m_byte_array:toUInt32();
    end

    function tvb_range:uint64()
        assert(self:len() <= 8, "tvbrange:uint64() cannot decode more than 8 bytes! (len = " .. self:len() .. ")");
        return UInt64.fromByteArray(self.m_byte_array);
    end;

    ---------------------------------------- little endian uint conversion ---------------------------------------------

    function tvb_range:le_uint()
        assert(self:len() <= 4, "tvbrange:le_uint() can only decode 4 bytes! (len = " .. self:len() .. ")");
        return self.m_byte_array:swapByteOrder():toUInt32();
    end

    function tvb_range:le_uint64()
        assert(self:len() <= 8, "tvbrange:le_uint64() cannot decode more than 8 bytes! (len = " .. self:len() .. ")");
        return UInt64.fromByteArray(self.m_byte_array:swapByteOrder());
    end;

    ------------------------------------------ big endian int conversion -----------------------------------------------

    function tvb_range:int(mask)
        local size = self:len();
        assert(size >= 1 and size <= 4, "TvbRange must be between 1 and 4 bytes long for TvbRange:int() to work. (TvbRange size: " .. self:len() ..")");
        local uint = self:uint();
        if mask then
            assert(type(mask) == "number" and mask == math.floor(mask) and mask <= UINT32_MAX, "When provided, the mask should be a 32 bit unsigned integer!");
            uint = bw.And(uint, mask);
        end
        local sign_mask=tonumber("80" .. string.rep("00", size-1), 16);
        if bw.And(uint, sign_mask) > 0 then --we're dealing with a negative number
            local val_mask=tonumber("7F" .. string.rep("FF", size-1), 16);
            local val = -(bw.And(bw.Not(uint), val_mask) + 1);
            return val;
        else --we are dealing with a positive number
            return uint;
        end
    end

    function tvb_range:int64(mask)
        if mask then
            return Int64.fromByteArray(self.m_byte_array):band(mask)
        end
        return Int64.fromByteArray(self.m_byte_array);
    end

    ---------------------------------------- little endian int conversion ----------------------------------------------

    function tvb_range:le_int(mask)
        local size = self:len();
        assert(size == 1 or size == 2 or size == 4, "TvbRange must be 1, 2, or 4 bytes long for TvbRange:le_int() to work. (TvbRange size: " .. self:len() ..")");
        return TvbRangeClass.new(self.m_byte_array:swapByteOrder()):int(mask);
    end

    function tvb_range:le_int64(mask)
        local size = self:len();
        assert(size == 1 or size == 2 or size == 4 or size == 8, "TvbRange must be 1, 2, 4, or 8 bytes long for TvbRange:le_int() to work. (TvbRange size: " .. self:len() ..")");
        return TvbRangeClass.new(self.m_byte_array:swapByteOrder()):int64(mask);
    end

    ------------------------------------------ big endian float conversion ---------------------------------------------

    function tvb_range:float()
        local size = self:len();
        assert(size == 4 or size == 8, "TvbRange must be 4 or 8 bytes long for TvbRange:float() to work. (TvbRange size: " .. self:len() ..")");
        if size == 4 then --32 bit float
            local uint = self:uint();
            --Handling special values nicely
            if uint == 0 or uint == 0x80000000 then
                return 0; --[[+/- zero]]
            elseif uint == 0x7F800000 then
                return math.huge --[[+infinity]]
            elseif uint == 0xFF800000 then
                return -math.huge --[[-infinity]]
            end
            local bit_len = 23;
            local exponent_mask = 0x7F800000;
            local exp = bw.Rshift(bw.And(uint, exponent_mask), bit_len);
            local fraction= 1;
            for i=1,bit_len do
                local bit_mask = bw.Lshift(1, (bit_len-i)); --looking at one bit at a time
                if bw.And(bit_mask, uint) > 0 then
                    fraction = fraction + math.pow(2,-i)
                end
            end
            local absolute_value = fraction * math.pow(2, exp -127);
            local sign = bw.And(uint, 0x80000000) > 0 and -1 or 1;
            return sign * absolute_value;
        else --64 bit float
            local word1 = self(0,4):uint(); --word1 will contain the bit sign, the exponent and part of the fraction
            local word2 = self(4,4):uint(); --word2 will contain the rest of the fraction
            --Handling special values nicely
            if word2 == 0 then
                if word1 == 0 or word1 == 0x80000000 then
                    return 0; --[[+/-zero]]
                elseif word1 == 0x7FF00000 then
                    return math.huge --[[+infinity]]
                elseif word1 == 0xFFF00000 then
                    return -math.huge --[[-infinity]]
                end
            end
            local exponent_mask = 0x7FF00000;
            local bit_len1 = 20;
            local exp = bw.Rshift(bw.And(word1, exponent_mask), bit_len1);
            local fraction= 1;
            for i=1,bit_len1 do --[[starting to calculate fraction with word1]]
                local bit_mask = bw.Lshift(1, (bit_len1-i)); --looking at one bit at a time
                if bw.And(bit_mask, word1) > 0 then
                    fraction = fraction + math.pow(2,-i)
                end
            end
            local bit_len2 = 32; --[[finishing to calculate fraction with word2]]
            for i=1,bit_len2 do
                local bit_mask = bw.Lshift(1, (bit_len2-i)); --looking at one bit at a time
                if bw.And(bit_mask, word2) > 0 then
                    fraction = fraction + math.pow(2,-i-bit_len1)
                end
            end
            local absolute_value = fraction * math.pow(2, exp - 1023);
            local sign = bw.And(word1, 0x80000000) > 0 and -1 or 1;
            return sign * absolute_value;
        end
    end

    ----------------------------------------- little endian float conversion -------------------------------------------

    function tvb_range:le_float()
        local size = self:len();
        assert(size == 4 or size == 8, "TvbRange must be 4 or 8 bytes long for TvbRange:le_float() to work. (TvbRange size: " .. self:len() ..")");
        return TvbRangeClass.new(self.m_byte_array:swapByteOrder()):float();
    end

    ------------------------------------------- big endian ipv4 conversion ---------------------------------------------

    function tvb_range:ipv4()
        assert(self:len() == 4, "TvbRange must by 4 bytes long for TvbRange:ipv4() to work. (TvbRange size: " .. self:len() ..")");
        return Utils.int32IPToString(self:int());
    end

    ------------------------------------------ litte endian ipv4 conversion --------------------------------------------

    function tvb_range:le_ipv4()
        assert(self:len() == 4, "TvbRange must by 4 bytes long for TvbRange:le_ipv4() to work. (TvbRange size: " .. self:len() ..")");
        return Utils.int32IPToString(self:le_int());
    end

    -------------------------------------- big endian ethernet address conversion --------------------------------------

    function tvb_range:eth()
        assert(self:len() == 6, "TvbRange must by 6 bytes long for TvbRange:eth() to work. (TvbRange size: " .. self:len() ..")");
        local eth_addr = "";
        for i=1,self:len() do
            local sep = i == 1 and "" or ":";
            eth_addr = eth_addr .. sep .. tostring(self(i-1,1):bytes());
        end
        return string.lower(eth_addr);
    end

    ------------------------------------------ big endian string conversion --------------------------------------------

    function tvb_range:string()
        local str = ""
        for i=0,(self:len() - 1) do
            local cur_byte = self.m_byte_array:subset(i,1):toHex(); --[[even a Protofield.string() stops printing after null character]]
            if cur_byte == '00' then --null char termination
                return str
            end
            str = str .. string.char(tonumber(cur_byte, 16))
        end
        str = string.gsub(str, ".", escape_replacements) --replacing escaped characters that characters that would cause io.write() or print() to mess up is they were interpreted
        return str
    end

    function tvb_range:stringz()
        local str = ""
        for i=0,(self:len() - 1) do
            local cur_byte = self.m_byte_array:subset(i,1):toHex(); --[[even a Protofield.string() stops printing after null character]]
            if cur_byte == '00' then --null char termination
                return str
            end
            str = str .. string.char(tonumber(cur_byte, 16))
        end
        str = string.gsub(str, ".", escape_replacements) --replacing escaped characters that characters that would cause io.write() or print() to mess up is they were interpreted
        return str
    end

    --[[TODO: this is not utf-16]]
    function tvb_range:ustring()
        return self:string();
    end

    --[[TODO: this is not utf-16]]
    function tvb_range:ustringz()
        return self:stringz();
    end

    ---------------------------------------- little endian string conversion -------------------------------------------

    function tvb_range:le_ustring()
        local be_hex_str = swapBytes(self:bytes():toHex());
        return TvbRangeClass.new(be_hex_str):ustring();
    end

    function tvb_range:le_ustringz()
        local be_hex_str = swapBytes(self:bytes():toHex());
        return TvbRangeClass.new(be_hex_str):ustringz();
    end

    ------------------------------------------- big endian GUID conversion ---------------------------------------------

    function tvb_range:guid()
        assert(self:len() == 16, "Trying to parse a GUID with length " .. self:len() .. "(Expecting 16 bytes)");
        local d = self.m_byte_array;
        return string.lower(tostring(d:subset(0,4)) .. "-" .. tostring(d:subset(4,2)) .. "-" ..
                tostring(d:subset(6,2)) .. "-" .. tostring(d:subset(8,2)) .. "-" .. tostring(d:subset(10,6)));
    end

    ------------------------------------------------ bitfield conversion -----------------------------------------------

    function tvb_range:bitfield(offset, length)
        offset = offset or 0;
        length = length or 1;
        assert(length <= 64, "Since bitfield() returns a uint64 of the bitfield, length must be <= 64 bits! (length: " .. length .. ")")
        local byte_offset = math.floor(offset/8);
        local byte_size = math.ceil((offset+length)/8) - byte_offset;
        local left_bits_count = offset % 8;
        local right_bits_count = (byte_size + byte_offset)*8 - (offset+length);
        assert(length == 8*byte_size - left_bits_count - right_bits_count); --[[number of bits up]]

        if length <= 32 then
            local uint_val = self(byte_offset, byte_size):uint64();
            local bit_mask = tonumber(string.rep("1", length),2);
            local uint64_masked_val = (uint_val:rshift(right_bits_count)):band(bit_mask);
            return uint64_masked_val:tonumber(); --since we're dealing with less than 32 bits, we can return a number

        else
            local high_bit_mask = tonumber(string.rep("1", 32 - left_bits_count),2);-- << left_bits_count;
            local bytes_as_uint64 = UInt64.fromByteArray(self.m_byte_array:subset(byte_offset, byte_size));
            return UInt64.new(bytes_as_uint64.m_low_word, bw.And(bytes_as_uint64.m_high_word, high_bit_mask)):rshift(right_bits_count);
        end
    end

    setmetatable(tvb_range, tvb_range)
    return tvb_range;
end

return TvbRangeClass;