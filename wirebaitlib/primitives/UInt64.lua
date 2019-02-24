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

local bw        = require("wirebaitlib.primitives.Bitwise");
local utils     = require("wirebaitlib.primitives.Utils");
local ByteArray = require("wirebaitlib.primitives.ByteArray");

--[[
    As of now, Lua does not support 64 bit integer. This class is meant to overcome that by providing a 64-bit unsigned
    integer arithmetic functionalities. An instance of this class can be instantiated using 2 32-bit unsigned integers.
    Alternatively, an instance call also be created from a ByteArray.

    //Constructor:
    <UInt64> UInt64.new(<number> num, <number> high_num)

    //Static method creating an UInt64 instance with min value
    <UInt64> UInt64.min()

    //Static method creating an UInt64 instance with max value
    <UInt64> UInt64.max()

    //Static method creating an UInt64 instance from a ByteArray
    <UInt64> UInt64.fromByteArray(<ByteArrayClass> byte_array)
]]
local UInt64 = {};

local UINT32_MAX = 0xFFFFFFFF;

function UInt64.new(num, high_num)
    local WORD_MASK = UINT32_MAX;
    assert(num and type(num) == "number" and num == math.floor(num) and num >= 0 and num <= UINT32_MAX, "UInt64.new(num), num must be a positive 32 bit integer!");
    assert(not high_num or (type(high_num) == "number" and high_num == math.floor(high_num) and high_num >= 0 and high_num <= UINT32_MAX), "UInt64.new(num, high_num): when provided, high_num must be a positive 32 bit integer!");
    local uint_64 = {
        _struct_type        = "UInt64",
        m_high_word         = high_num or 0,
        m_low_word          = num,
        m_decimal_value_str = ""
    }

    --TODO: there has to be a better, easier, simpler way than having to use this. Look back at it when you have time.
    local POW_OF_2_STRS = {
        [53] = "9007199254740992",    -- 2^53
        [54] = "18014398509481984",   -- 2^54
        [55] = "36028797018963968",   -- 2^55
        [56] = "72057594037927936",   -- 2^56
        [57] = "144115188075855872",  -- 2^57
        [58] = "288230376151711744",  -- 2^58
        [59] = "576460752303423488",  -- 2^59
        [60] = "1152921504606846976", -- 2^60
        [61] = "2305843009213693952", -- 2^61
        [62] = "4611686018427387904", -- 2^62
        [63] = "9223372036854775808"  -- 2^63
    }

    ----------------------------------------------- private methods ----------------------------------------------------

    --[[Function adding two strings reprensting unsigned integers in base 10. The result is also a string
      e.g. decimalStrAddition("10","14") returns "24"]]
    local function decimalStrAddition(str1, str2)  --PRIVATE METHOD
        assert(str1 and type(str1) == "string" and #str1 > 0 and #str1 <= 20, "decimalStrAddition() invalid parameters!");
        assert(str2 and type(str2) == "string" and #str2 > 0 and #str2 <= 20, "decimalStrAddition() invalid parameters!");
        local long_str = str1;
        local short_str = str2;
        if #long_str < #short_str then
            long_str = str2;
            short_str = str1;
        end

        local result = "";
        local carry = 0;
        for i = 1,#long_str do
            local v = string.sub(long_str, -i, -i);
            v = v + carry;
            carry = 0;
            if i <= #short_str then
                v = v + string.sub(short_str, -i, -i);
            end
            if v >= 10 then
                result = math.floor(v % 10) .. result;
                carry = math.floor(v / 10)
            else
                result = math.floor(v) .. result;
            end
        end
        if carry > 0 then
            result = math.floor(carry) .. result;
        end
        return result;
    end

    local function decimalStrFromWords(low_word, high_word)  --PRIVATE METHOD
        if high_word < 0x200000 then --the uint64 value is less than 2^53
            return tostring(("%.17g"):format(math.floor(bw.Lshift(high_word, 32) + low_word)));
        else --above or equal to 2^53, values lose integer precision
            local high_word_low = bw.And(high_word, 0x1FFFFF);
            local value_str = tostring(("%.17g"):format(math.floor(bw.Lshift(high_word_low, 32) + low_word))); --we get the value up until the 53rd bits in a "classic way"
            for i=1,11 do --[[For the remaining 11 bits we have to use some trickery to not loose int precision]]
                local bit = bw.Lshift(1, (32 - i));
                if bw.And(high_word, bit) > 0 then
                    value_str = decimalStrAddition(value_str, POW_OF_2_STRS[64-i]);
                end
            end
            return value_str;
        end
    end

    --[[Given a number of an UInt64, returns the two 4-byte words that make up that number]]
    local function getWords(num_or_uint) --PRIVATE METHOD
        assert(num_or_uint and utils.typeof(num_or_uint) == "UInt64" or utils.typeof(num_or_uint) == "number", "Argument needs to be a number or a UInt64!");
        local low_word = 0;
        local high_word = 0;
        if utils.typeof(num_or_uint) == "UInt64" then
            low_word = num_or_uint.m_low_word;
            high_word = num_or_uint.m_high_word;
        else
            assert(math.floor(num_or_uint) == num_or_uint, "UInt64 cannot deal with numbers without integer precision!");
            low_word = bw.And(num_or_uint, WORD_MASK);
            high_word = bw.And(bw.Rshift(num_or_uint, 32), WORD_MASK);
        end
        return low_word, high_word;
    end

    ----------------------------------------------- initialization -----------------------------------------------------

    uint_64.m_decimal_value_str = decimalStrFromWords(uint_64.m_low_word, uint_64.m_high_word);

    ------------------------------------------------- metamethods ------------------------------------------------------

    function uint_64:__tostring()
        return uint_64.m_decimal_value_str;
    end

    function uint_64.__lt(uint_or_num1, uint_or_num2)
        local low_word1, high_word1 = getWords(uint_or_num1);
        local low_word2, high_word2 = getWords(uint_or_num2);
        if high_word1 < high_word2 then
            return true;
        else
            return low_word1 < low_word2;
        end
    end

    function uint_64.__eq(uint_or_num1, uint_or_num2)
        local low_word1, high_word1 = getWords(uint_or_num1);
        local low_word2, high_word2 = getWords(uint_or_num2);
        return low_word1 == low_word2 and high_word1 == high_word2;
    end

    function uint_64.__le(uint_or_num1, uint_or_num2)
        assert(uint_or_num1 and utils.typeof(uint_or_num1) == "number" or utils.typeof(uint_or_num1) == "UInt64", "Argument #1 needs to be a number or a UInt64!");
        assert(uint_or_num2 and utils.typeof(uint_or_num2) == "number" or utils.typeof(uint_or_num2) == "UInt64", "Argument #2 needs to be a number or a UInt64!");
        return uint_or_num1 < uint_or_num2 or uint_or_num1 == uint_or_num2;
    end

    function uint_64.__add(uint_or_num1, uint_or_num2)
        local low_word1, high_word1 = getWords(uint_or_num1);
        local low_word2, high_word2 = getWords(uint_or_num2);

        local function local_add(word1, word2, init_carry)
            word1 = bw.And(word1, WORD_MASK);
            word2 = bw.And(word2, WORD_MASK);
            local result = 0;
            local c = init_carry or 0;
            for i = 0,31 do
                local bw1 = bw.And(bw.Rshift(word1, i), 1);
                local bw2 = bw.And(bw.Rshift(word2, i), 1);
                result = bw.Or(result, bw.Lshift(bw.Xor(bw.Xor(bw1,bw2), c), i));
                c = (bw1 + bw2 + c) > 1 and 1 or 0;
            end
            return result, c;
        end

        local new_low_word, carry = local_add(low_word1, low_word2);
        local new_high_word = local_add(high_word1, high_word2, carry);
        return UInt64.new(new_low_word, new_high_word);
    end

    function uint_64.__sub(uint_or_num1, uint_or_num2)
        local low_word1, high_word1 = getWords(uint_or_num1);
        local low_word2, high_word2 = bw.twosComplement(getWords(uint_or_num2)); -- taking advantage of the fact that (A-B)=(A+bw.twosComplement(B))
        return UInt64.new(low_word1, high_word1) + UInt64.new(low_word2, high_word2);
    end

    function uint_64.__band(num_or_uint1, num_or_uint2) --[[bitwise AND operator (&)]]
        local low_word1, high_word1 = getWords(num_or_uint1);
        local low_word2, high_word2 = getWords(num_or_uint2);
        return UInt64.new(bw.And(low_word1, low_word2), bw.And(high_word1, high_word2))
    end

    function uint_64:__bnot() --[[bitwise NOT operator (unary ~)]]
        return UInt64.new(bw.And(bw.Not(self.m_low_word), WORD_MASK), bw.And(bw.Not(self.m_high_word), WORD_MASK))
    end

    function uint_64.__bor(uint_or_num1, uint_or_num2) --[[bitwise OR operator (|)]]
        local low_word1, high_word1 = getWords(uint_or_num1);
        local low_word2, high_word2 = getWords(uint_or_num2);
        return UInt64.new(bw.Or(low_word1, low_word2), bw.Or(high_word1, high_word2))
    end

    function uint_64.__bxor(uint_or_num1, uint_or_num2) --[[bitwise XOR operator (binary ~)]]
        local low_word1, high_word1 = getWords(uint_or_num1);
        local low_word2, high_word2 = getWords(uint_or_num2);
        return UInt64.new(bw.Xor(low_word1, low_word2), bw.Xor(high_word1, high_word2))
    end

    function uint_64:__shl(shift) --[[bitwise left shift (<<)]]
        assert(type(shift) == "number" and shift == math.floor(shift), "The shift must be an integer!")
        if shift < 32 then
            local new_high_word = bw.Rshift(self.m_low_word, (32-shift)) + bw.And(bw.Lshift(self.m_high_word, shift), WORD_MASK);
            return UInt64.new(bw.And(bw.Lshift(self.m_low_word, shift), WORD_MASK), new_high_word);
        elseif shift < 64 then
            return UInt64.new(0, bw.And(bw.Lshift(self.m_low_word, (shift-32)), WORD_MASK));
        else
            return UInt64.new(0, 0);
        end
    end

    function uint_64:__shr(shift) --[[bitwise right shift (>>)]]
        assert(type(shift) == "number" and shift == math.floor(shift), "The shift must be an integer!")
        if shift < 32 then
            --local new_low_word = bw.Rshift(self.m_low_word, shift) + bw.And(bw.Lshift(self.m_high_word, (32-shift)), WORD_MASK);
            local new_low_word = bw.Rshift(self.m_low_word, shift) + bw.Lshift(bw.And(self.m_high_word, tonumber("0" .. string.rep("1", shift), 2)), 32-shift); --TODO: super hacky, fix this!
            return UInt64.new(new_low_word, bw.Rshift(self.m_high_word, shift));
        elseif shift < 64 then
            return UInt64.new(bw.And(bw.Lshift(self.m_high_word, (shift-32)), WORD_MASK), 0);
        else
            return UInt64.new(0, 0);
        end
    end

    ------------------------------------------------ public methods ----------------------------------------------------

    function uint_64:lshift(shift) --[[left shift operation]]
        return self:__shl(shift);
    end

    function uint_64:rshift(shift) --[[right shift operation]]
        return self:__shr(shift);
    end

    function uint_64:band(...) --[[logical AND]]
        local result = self;
        for _,val in ipairs({...}) do
            result = result:__band(val);
        end
        return result;
    end

    function uint_64:bor(...) --[[logical OR]]
        local result = self;
        for _,val in ipairs({...}) do
            result = result:__bor(val);
        end
        return result;
    end

    function uint_64:bxor(...) --[[logical XOR]]
        local result = self;
        for _,val in ipairs({...}) do
            result = result:__bxor(val);
        end
        return result;
    end

    function uint_64:bnot()
        return self:__bnot();
    end

    function uint_64:tonumber() --[[may lose integer precision if the number is greater than 2^53]]
        return tonumber(self.m_decimal_value_str);
    end

    function uint_64:tohex(num_chars)
        assert(not num_chars or (type(num_chars) == "number" and math.floor(num_chars) == num_chars and num_chars > 0), "If provided argument #1 needs to be a positive integer!");
        num_chars = num_chars or 16;
        local hex_str = string.format("%8X", self.m_high_word) .. string.format("%8X", self.m_low_word);
        if num_chars < 16 then
            hex_str = hex_string:sub(-num_chars, -1);
        elseif num_chars > 16 then
            hex_str = string.format("%" .. num_chars .. "s", hex_str);
        end
        return hex_str:gsub(" ", "0");
    end

    function uint_64:lower()
        return self.m_low_word;
    end

    function uint_64:higher()
        return self.m_high_word;
    end

    setmetatable(uint_64, uint_64)
    return uint_64;
end


-------------------------------------------------- static methods ------------------------------------------------------
--TODO: enfore byte_array size to 8 bytes?
--TODO: add endianness to function name
--[[ Creates a UInt64 instance from the first 8 bytes of the provided ByteArray]]
function UInt64.fromByteArray(byte_array)
    assert(byte_array and utils.typeof(byte_array) == "ByteArray", "Argurment #1 should be a ByteArray!");
    assert(byte_array:len() > 0, "ByteArray cannot be empty!");
    assert(byte_array:len() <= 8, "ByteArray cannot contain more than 8 bytes!");

    if (byte_array:len() < 8) then
        local b = ByteArray.new("");
        b:set_size(8 - byte_array:len());
        byte_array:prepend(b)
    end

    local high_num = tonumber(byte_array:subset(0,4):toHex(),16);
    local num = tonumber(byte_array:subset(4,4):toHex(),16);
    return UInt64.new(num, high_num);
end

--[[Returns a UInt64 instance of maximum value]]
function UInt64.max()
    return UInt64.new(UINT32_MAX, UINT32_MAX);
end

--[[Returns a UInt64 instance of value 0]]
function UInt64.min()
    return UInt64.new(0, 0);
end

return UInt64;