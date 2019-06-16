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

local UInt64    = require("wirebaitlib.primitives.UInt64");
local bw        = require("wirebaitlib.primitives.Bitwise");
local ByteArray = require("wirebaitlib.primitives.ByteArray");
local utils     = require("wirebaitlib.primitives.Utils");

--[[
    As of now, Lua does not support 64 bit integers. This class is meant to overcome that by providing a 64-bit signed
    integer arithmetic functionalities. An instance of this class can be instantiated using 2 32-bit integers.
    Alternatively, an instance call also be created from a ByteArray.

    //Constructor:
    <Int64> Int64Class.new(<number> num, <number> high_num)

    //Static method creating an Int64 instance with min value
    <Int64> Int64Class.min()

    //Static method creating an Int64 instance with max value
    <Int64> Int64Class.max()

    //Static method creating an Int64 instance from a ByteArray
    <Int64> Int64Class.fromByteArray(<ByteArrayClass> byte_array)
]]
local Int64Class = {};

---------------------------------------------- private static variables ------------------------------------------------
local UINT32_MAX = 0xFFFFFFFF;-- 32 bit word
local SIGN_MASK = 0x80000000;
local WORD_MASK = UINT32_MAX;


------------------------------------------------- private methods ------------------------------------------------------
local function getWords(num_or_int) --PRIVATE METHOD
    assert(num_or_int and type(num_or_int) == number or utils.typeof(num_or_int) == "Int64", "Argument #1 must be a number or Int64!");
    local low_word = 0;
    local high_word = 0;
    local is_negative_number = false;
    if utils.typeof(num_or_int) == "Int64" then
        low_word = num_or_int.m_low_word;
        high_word = num_or_int.m_high_word;
        is_negative_number = bw.And(high_word, SIGN_MASK) > 0;
    else
        assert(math.floor(num_or_int) == num_or_int, "Int64 cannot deal with numbers without integer precision!");
        is_negative_number = num_or_int < 0;
        low_word = bw.And(num_or_int, WORD_MASK);
        high_word = bw.And(bw.Rshift(num_or_int, 32), WORD_MASK);
    end
    return low_word, high_word, is_negative_number;
end


------------------------------------------ Instance used to define class methods ---------------------------------------
local int_64 = {};
int_64.__index = int_64;


--------------------------------------------------- metamethods --------------------------------------------------------
function int_64:__tostring()
    if bw.And(self.m_high_word, SIGN_MASK) > 0 then
        return "-" .. tostring(UInt64.new(bw.twosComplement(self.m_low_word, self.m_high_word)))
    end
    return tostring(UInt64.new(self.m_low_word, self.m_high_word));
end

function int_64.__lt(int_or_num1, int_or_num2)
    local low_word1, high_word1, neg1 = getWords(int_or_num1);
    local low_word2, high_word2, neg2 = getWords(int_or_num2);
    if neg1 ~= neg2 then
        return neg1 and true or false;
    end
    if high_word1 < high_word2 then
        return neg1 and false or true;
    else
        return neg1 and low_word1 > low_word2 or low_word1 < low_word2;
    end
end

function int_64.__eq(int_or_num1, int_or_num2)
    local low_word1, high_word1, neg1 = getWords(int_or_num1);
    local low_word2, high_word2, neg2 = getWords(int_or_num2);
    return neg1 == neg2 and low_word1 == low_word2 and high_word1 == high_word2;
end

function int_64.__le(int_or_num1, int_or_num2)
    return int_or_num1 < int_or_num2 or int_or_num1 == int_or_num2;
end

function int_64.__add(int_or_num1, int_or_num2)
    local low_word1, high_word1, neg1 = getWords(int_or_num1);
    local low_word2, high_word2, neg2 = getWords(int_or_num2);

    local function local_add(word1, word2, init_carry)
        word1 = bw.And(word1, WORD_MASK);
        word2 = bw.And(word2, WORD_MASK);
        local result = 0;
        local c = init_carry or 0;
        for i = 0,31 do
            local bw1 = bw.And(bw.Rshift(word1, i), 1);
            local bw2 = bw.And(bw.Rshift(word2, i), 1);
            result = bw.Or(result, bw.Lshift(bw.Xor(bw.Xor(bw1, bw2), c), i));
            c = (bw1 + bw2 + c) > 1 and 1 or 0;
        end
        return result, c;
    end

    local new_low_word, carry = local_add(low_word1, low_word2);
    local new_high_word = local_add(high_word1, high_word2, carry);
    return Int64Class.new(new_low_word, new_high_word);
end

function int_64.__sub(int_or_num1, int_or_num2)
    local low_word1, high_word1, neg1 = getWords(int_or_num1);
    local low_word2, high_word2, neg2 = bw.twosComplement(getWords(int_or_num2)); --taking advantage of the fact that A-B = A+(-B) and (-B) = twosComplement of B
    return Int64Class.new(low_word1, high_word1) + Int64Class.new(low_word2, high_word2)
end

function int_64.__band(int_or_num1, int_or_num2) --[[bitwise AND operator (&)]]
    local low_word1, high_word1 = getWords(int_or_num1);
    local low_word2, high_word2 = getWords(int_or_num2);
    return Int64Class.new(bw.And(low_word1, low_word2), bw.And(high_word1, high_word2))
end

function int_64:__bnot() --[[bitwise NOT operator (unary ~)]]
    return Int64Class.new(bw.And(bw.Not(self.m_low_word), WORD_MASK), bw.And(bw.Not(self.m_high_word), WORD_MASK))
end

function int_64.__bor(int_or_num1, int_or_num2) --[[bitwise OR operator (|)]]
    local low_word1, high_word1 = getWords(int_or_num1);
    local low_word2, high_word2 = getWords(int_or_num2);
    return Int64Class.new(bw.Or(low_word1, low_word2), bw.Or(high_word1, high_word2))
end

function int_64.__bxor(int_or_num1, int_or_num2) --[[bitwise XOR operator (binary ~)]]
    local low_word1, high_word1 = getWords(int_or_num1);
    local low_word2, high_word2 = getWords(int_or_num2);
    return Int64Class.new(bw.Xor(low_word1, low_word2), bw.Xor(high_word1, high_word2))
end

function int_64:__shl(shift) --[[bitwise left shift (<<)]]
    assert(shift and type(shift) == "number" and shift == math.floor(shift), "The shift must be an integer!")
    if shift < 32 then
        local new_high_word = bw.Rshift(self.m_low_word, (32-shift)) + bw.And(bw.Lshift(self.m_high_word, shift), WORD_MASK);
        return UInt64.new(bw.And(bw.Lshift(self.m_low_word, shift), WORD_MASK), new_high_word);
    elseif shift < 64 then
        return UInt64.new(0, bw.And(bw.Lshift(self.m_low_word, (shift-32)), WORD_MASK));
    else
        return UInt64.new(0, 0);
    end
end

function int_64:__shr(shift) --[[bitwise right shift (>>)]]
    assert(shift and type(shift) == "number" and shift == math.floor(shift), "The shift must be an integer!")
    if shift < 32 then
        local new_low_word = bw.Rshift(self.m_low_word, shift) + bw.And(bw.Lshift(self.m_high_word, (32-shift)), WORD_MASK);
        return UInt64.new(new_low_word, bw.Rshift(self.m_high_word, shift));
    elseif shift < 64 then
        return Int64Class.new(bw.And(bw.Lshift(self.m_high_word, (shift-32)), WORD_MASK), 0);
    else
        return Int64Class.new(0, 0);
    end
end

-------------------------------------------------- public methods ------------------------------------------------------
function int_64:lshift(shift) --[[left shift operation]]
    return self:__shl(shift);
end

function int_64:rshift(shift) --[[right shift operation]]
    return self:__shr(shift);
end

function int_64:band(...) --[[logical AND]]
    local result = self;
    for _,val in ipairs({...}) do
        result = result:__band(val);
    end
    return result;
end

function int_64:bor(...) --[[logical OR]]
    local result = self;
    for _,val in ipairs({...}) do
        result = result:__bor(val);
    end
    return result;
end

function int_64:bxor(...) --[[logical XOR]]
    local result = self;
    for _,val in ipairs({...}) do
        result = result:__bxor(val);
    end
    return result;
end

function int_64:bnot()
    return self:__bnot();
end

function int_64:tonumber() --[[may lose integer precision if the number is greater than 2^53]]
    assert(false, "int64:tonumber() is not available yet!")
end

function int_64:tohex(num_chars)
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

function int_64:lower()
    return self.m_low_word;
end

function int_64:higher()
    return self.m_high_word;
end


---------------------------------------------------- Constructor -------------------------------------------------------
function Int64Class.new(num, high_num)
    assert(num and type(num) == "number" and num >= 0 and num <= UINT32_MAX and num == math.floor(num), "Int64.new(num), num must be a positive 32 bit integer!");
    assert(not high_num or (type(high_num) == "number" and high_num >= 0 and high_num <= UINT32_MAX and high_num == math.floor(high_num)), "Int64.new(num, high_num): when provided, high_num must be a positive 32 bit integer!");
    local new_int64 = {
        _struct_type = "Int64",
        m_low_word = num,
        m_high_word = high_num or 0,
    }

    setmetatable(new_int64, int_64)
    return new_int64;
end


-------------------------------------------------- static methods ------------------------------------------------------
--TODO: enforce byte_array size to 8 bytes?
--TODO: add endianness to function name
--TODO: add unit tests
function Int64Class.fromByteArray(byte_array)
    assert(byte_array and utils.typeof(byte_array) == "ByteArray", "Argurment #1 should be a ByteArray!");
    assert(byte_array:len() > 0, "ByteArray cannot be empty!");
    assert(byte_array:len() <= 8, "ByteArray cannot contain more than 8 bytes!");

    local array = nil;
    if (byte_array:len() < 8) then
        array = ByteArray.new(byte_array:toHex()); -- We need to make a copy otherwise we would modify the provided array
        local prefix_array = ByteArray.new("");
        prefix_array:set_size(8 - byte_array:len());
        array:prepend(prefix_array);
    else
        array = byte_array; -- Here we don't have to make a copy
    end

    local high_num = tonumber(array:subset(0,4):toHex(),16);
    local num = tonumber(array:subset(4,4):toHex(),16);
    return Int64Class.new(num, high_num);
end

function Int64Class.max()
    return Int64Class.new(UINT32_MAX, 0x7FFFFFFF);
end

function Int64Class.min()
    return Int64Class.new(0, 0x80000000);
end

return Int64Class;