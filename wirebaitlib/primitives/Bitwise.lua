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

-- Unlike other libraries, function are capitalized to avoid lua syntax errors

--TODO: I should probaly get rid of this library as it provides very little value

local Bitwise = {};

--[[Bitwise operations]]
local UINT32_MAX = 0xFFFFFFFF;-- 32 bit word
local WORD_MASK = UINT32_MAX;

function Bitwise.And(int1, int2) --TODO: enforce uint32 params!
    assert(int1 and type(int1) == "number" and math.floor(int1) == int1, "Expecting integer");
    assert(int2 and type(int2) == "number" and math.floor(int2) == int2, "Expecting integer");
    return bit32.band(int1, int2);
end

function Bitwise.Lshift(int1, int2)
    assert(int1 and type(int1) == "number" and math.floor(int1) == int1, "Expecting integer");
    assert(int2 and type(int2) == "number" and math.floor(int2) == int2, "Expecting integer");
    return int1 * math.pow(2,int2);
end

function Bitwise.Rshift(int1, int2)
    assert(int1 and type(int1) == "number" and math.floor(int1) == int1, "Expecting integer");
    assert(int2 and type(int2) == "number" and math.floor(int2) == int2, "Expecting integer");
    return bit32.rshift(int1, int2);
end

function Bitwise.Or(int1, int2)
    assert(int1 and type(int1) == "number" and math.floor(int1) == int1, "Expecting integer");
    assert(int2 and type(int2) == "number" and math.floor(int2) == int2, "Expecting integer");
    return bit32.bor(int1, int2);
end

function Bitwise.Xor(int1, int2)
    assert(int1 and type(int1) == "number" and math.floor(int1) == int1, "Expecting integer");
    assert(int2 and type(int2) == "number" and math.floor(int2) == int2, "Expecting integer");
    return bit32.bxor(int1, int2);
end

function Bitwise.Not(int1)
    assert(int1 and type(int1) == "number" and math.floor(int1) == int1, "Expecting unsigned");
    return bit32.bnot(int1);
end

--[[Two's complement of a 64 bit value represented by two 4-byte values]]
function Bitwise.twosComplement(low_word, high_word)
    local new_low_word = Bitwise.And(Bitwise.Not(low_word), WORD_MASK) + 1;
    local new_high_word = Bitwise.And(Bitwise.Not(high_word), WORD_MASK);
    if new_low_word > WORD_MASK then --there's a carry from low to high word
        new_low_word = 0;
        new_high_word = Bitwise.And((new_high_word + 1), WORD_MASK);
    end
    return new_low_word, new_high_word;
end

return Bitwise;