--[[
    WireBait for Wireshark is a lua package to help write Wireshark 
    Dissectors in lua.
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

local wirebait = { 
  UInt64 = {},
  Int64 = {},
  Proto = {}, 
  base = { NONE=0, DEC=1, HEX=2, OCT=3, DEC_HEX=4, HEX_DEC=5}, --[[c.f. [Wireshark Repo](https://github.com/wireshark/wireshark/blob/537705a8b20ee89bf1f713bc0c9959cf21b26900/test/lua/globals_2.2.txt) ]]
  ProtoField = {}, 
  treeitem = {}, 
  buffer = {}, 
  packet = {}, 
  pcap_reader = {}, 
  plugin_tester = {},

  state = { --[[ state to keep track of the dissector wirebait is testing ]]
    dissector_filepath = nil,
    proto = nil,
    packet_info = { --TODO should be reset after each packet
      cols={
        protocol = nil
      },
      treeitems_array = {} --treeitems are added to that array so they can be displayed after the whole packet is dissected
    },
    dissector_table = {
      udp = { port = nil },
      tcp = { port = nil }
    }
  }
}

if _VERSION ~= "Lua 5.3" then
  error("WireBait has only been developed with Lua 5.3. Try it with another version at your own risk OR feel free to create a ticket @ https://github.com/MarkoPaul0/WireBait")
end

--[[----------LOCAL HELPER METHODS (only used within the library)---------------------------------------------------------------------------------------------------------]]
--[[Reads byte_count bytes from file into a string in hexadecimal format ]]
local function readFileAsHex(file, byte_count)
  local data = file:read(byte_count) --reads the binary data into a string. When printed this is gibberish
  data = data or "";
  local hex_data = string.gsub(data, ".", function (b) return string.format("%02X",string.byte(b)) end ) --turns the binary data into a string in hex format
  return hex_data
end

--[[Prints an ip in octet format givent its little endian int32 representation]]
local function printIP(le_int_ip)
  local ip_str = ((le_int_ip & 0xFF000000) >> 24) .. "." .. ((le_int_ip & 0x00FF0000) >> 16) .. "." .. ((le_int_ip & 0x0000FF00) >> 8) .. "." .. (le_int_ip & 0x000000FF);
  return ip_str;
end

--[[Switches byte order of the given hex_str. For instance the input "12ABCDEF" will be turned into "EFCDAB12" ]]
local function swapBytes(hex_str)
  local new_hex_str = "";
  for i=1,#hex_str/2 do
    new_hex_str = hex_str:sub(2*i-1,2*i) .. new_hex_str;
  end
  return new_hex_str;
end

--[[Decode a uint32 from a hexadecimal string]]
local function hexStringToUint32(hex_str)
  --TODO: check if valid hexadecimal string [NO WHITE SPACE!]
  assert(#hex_str > 0, "hexStringToUint32() requires strict positive number of bytes!");
  assert(#hex_str <= 32, "hexStringToUint32() cannot convert more thant 4 bytes to a uint value!");
  hex_str = string.format("%016s",hex_str):gsub(" ","0") --left pad with zeros
  return tonumber(hex_str, 16);
end

--[[Two's complement of a 64 bit value ]]
local UINT32_MAX = 0xFFFFFFFF;-- 32 bit word
local WORD_MASK = UINT32_MAX; 
local function twosComplement(low_word, high_word)
  local new_low_word = ((~low_word) & WORD_MASK) + 1;
  local new_high_word = (~high_word) & WORD_MASK;
  if new_low_word > WORD_MASK then --there's a carry from low to high word
    new_low_word = 0;
    new_high_word = (new_high_word + 1) & WORD_MASK;
  end
  return new_low_word, new_high_word;
end

local PROTOCOL_TYPES = {
  IPV4 = 0x800,
  UDP  = 0x11,
  TCP  =  0x06
};
--[-----------------------------------------------------------------------------------------------------------------------------------------------------------------------]]


--[----------WIRESHARK UINT64----------------------------------------------------------------------------------------------------------------------------------------------]]
function wirebait.UInt64.new(num, high_num)
  assert(num and type(num) == "number" and num == math.floor(num) and num >= 0 and num <= UINT32_MAX, "UInt64.new(num), num must be a positive 32 bit integer!");
  assert(not high_num or (type(high_num) == "number" and high_num == math.floor(high_num) and high_num >= 0 and high_num <= UINT32_MAX), "UInt64.new(num, high_num): when provided, high_num must be a positive 32 bit integer!");
  local uint_64 = {
    _struct_type = "UInt64",
    m_high_word = high_num or 0,
    m_low_word = num,
    m_decimal_value_str = "",
  }
  
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

  local function decimalStrAddition(str1, str2)  --PRIVATE METHOD
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
    if high_word < 0x200000 then --the uint64 value is less than 2^53-1
      return tostring(math.floor((high_word << 32) + low_word));
    else --above or equal to 2^53, values lose integer precision 
      local high_word_low = high_word & 0x1FFFFF;
      local value_str = tostring(math.floor((high_word_low << 32) + low_word)); --we get the value up until the 53rd bits in a "classic way"
      for i=1,11 do --[[For the remaining 11 bits we have to use some trickery to not loose int precision]]
        local bit = 1 << (32 - i);
        if high_word & bit > 0 then
          value_str = decimalStrAddition(value_str, POW_OF_2_STRS[64-i]);
        end
      end
      return value_str;
    end
  end
  
  uint_64.m_decimal_value_str = decimalStrFromWords(uint_64.m_low_word, uint_64.m_high_word);
  
  function uint_64:__tostring()
    return uint_64.m_decimal_value_str;
  end
  
  local function getWords(num_or_uint) --PRIVATE METHOD
    local low_word = 0;
    local high_word = 0;
    local is_negative_number = false;
    if type(num_or_uint) == "table" then
      assert(num_or_uint._struct_type == "UInt64", "Argument needs to be a number or a UInt64!")
      low_word = num_or_uint.m_low_word;
      high_word = num_or_uint.m_high_word;
    else
      if num_or_uint < 0 then
        is_negative_number = true;
      end
      assert(type(num_or_uint) == "number", "Argument needs to be a number or a UInt64!")
      low_word = num_or_uint & WORD_MASK;
      high_word = (num_or_uint >> 32) & WORD_MASK;
    end
    return low_word, high_word, is_negative_number;
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
    return uint_or_num1 < uint_or_num2 or uint_or_num1 == uint_or_num2;
  end
  
  function uint_64.__add(uint_or_num1, uint_or_num2)
    local low_word1, high_word1, neg1 = getWords(uint_or_num1);
    local low_word2, high_word2, neg2 = getWords(uint_or_num2);
    
    local function ADD(word1, word2, init_carry)
      word1 = word1 & WORD_MASK;
      word2 = word2 & WORD_MASK;
      local result = 0;
      local c = init_carry or 0;
      for i = 0,31 do
        local bw1 = (word1 >> i) & 1;
        local bw2 = (word2 >> i) & 1;
        result = result | ((bw1 ~ bw2 ~ c) << i);
        c = (bw1 + bw2 + c) > 1 and 1 or 0;
      end
      return result, c;
    end
    
    local new_low_word, carry = ADD(low_word1, low_word2);
    local new_high_word = ADD(high_word1, high_word2, carry);
    return wirebait.UInt64.new(new_low_word, new_high_word);
  end
  
  function uint_64.__sub(uint_or_num1, uint_or_num2)
    local low_word1, high_word1 = getWords(uint_or_num1);
    local low_word2, high_word2 = twosComplement(getWords(uint_or_num2));
    return wirebait.UInt64.new(low_word1, high_word1) + wirebait.UInt64.new(low_word2, high_word2);
  end

  function uint_64.__band(self, other) --[[bitwise AND operator (&)]]
    if type(other) == "table" and other._struct_type == "UInt64" then
      local tmp = other;
      other = self;
      self = tmp;
    end
    local o_low_word = 0;
    local o_high_word = 0;
    if type(other) == "number" then
      o_low_word = other & WORD_MASK;
      o_high_word = (other >> 32) & WORD_MASK;
    elseif other._struct_type == "UInt64" then
      o_low_word = other.m_low_word;
      o_high_word = other.m_high_word;
    else
      error("Cannot perform bitwise operation between UInt64 and " .. type(other));
    end
    return wirebait.UInt64.new(self.m_low_word & o_low_word, self.m_high_word & o_high_word)
  end
  
  function uint_64:__bnot() --[[bitwise NOT operator (unary ~)]]
    return wirebait.UInt64.new(~self.m_low_word & WORD_MASK, ~self.m_high_word & WORD_MASK)
  end
  
  function uint_64.__bor(self, other) --[[bitwise OR operator (|)]]
    if type(other) == "table" and other._struct_type == "UInt64" then
      local tmp = other;
      other = self;
      self = tmp;
    end
    local o_low_word = 0;
    local o_high_word = 0;
    if type(other) == "number" then
      o_low_word = other & WORD_MASK;
      o_high_word = (other >> 32) & WORD_MASK;
    elseif other._struct_type == "UInt64" then
      o_low_word = other.m_low_word;
      o_high_word = other.m_high_word;
    else
      error("Cannot perform bitwise operation between UInt64 and " .. type(other));
    end
    return wirebait.UInt64.new(self.m_low_word | o_low_word, self.m_high_word | o_high_word)
  end
  
  function uint_64.__bxor(self, other) --[[bitwise XOR operator (binary ~)]]
    if type(other) == "table" and other._struct_type == "UInt64" then
      local tmp = other;
      other = self;
      self = tmp;
    end
    local o_low_word = 0;
    local o_high_word = 0;
    if type(other) == "number" then
      o_low_word = other & WORD_MASK;
      o_high_word = (other >> 32) & WORD_MASK;
    elseif other._struct_type == "UInt64" then
      o_low_word = other.m_low_word;
      o_high_word = other.m_high_word;
    else
      error("Cannot perform bitwise operation between UInt64 and " .. type(other));
    end
    return wirebait.UInt64.new(self.m_low_word ~ o_low_word, self.m_high_word ~ o_high_word)
  end
  
  function uint_64:__shl(shift) --[[bitwise left shift (<<)]]
    assert(type(shift) == "number" and shift == math.floor(shift), "The shift must be an integer!")
    if shift < 32 then
      local new_high_word = (self.m_low_word >> (32-shift)) + ((self.m_high_word << shift) & WORD_MASK);
      return wirebait.UInt64.new((self.m_low_word << shift) & WORD_MASK, new_high_word);
    elseif shift < 64 then
      return wirebait.UInt64.new(0, (self.m_low_word << (shift-32)) & WORD_MASK);
    else
      return wirebait.UInt64.new(0, 0);
    end
  end
  
  function uint_64:__shr(shift) --[[bitwise right shift (>>)]]
    assert(type(shift) == "number" and shift == math.floor(shift), "The shift must be an integer!")
    if shift < 32 then
      local new_low_word = (self.m_low_word >> shift) + ((self.m_high_word << (32-shift)) & WORD_MASK);
      return wirebait.UInt64.new(new_low_word, self.m_high_word >> shift);
    elseif shift < 64 then
      return wirebait.UInt64.new((self.m_high_word << (shift-32)) & WORD_MASK, 0);
    else
      return wirebait.UInt64.new(0, 0);
    end
  end

  function uint_64:lshift(shift) --[[left shift operation]]
    return self << shift;
  end
  
  function uint_64:rshift(shift) --[[right shift operation]]
    return self >> shift;
  end
  
  function uint_64:band(...) --[[logical AND]]
    local result = self;
    for _,val in ipairs({...}) do
        result = result & val;
      end
    return result;
  end
  
  function uint_64:bor(...) --[[logical OR]]
    local result = self;
    for _,val in ipairs({...}) do
        result = result | val;
      end
    return result;
  end
  
  function uint_64:bxor(...) --[[logical XOR]]
    local result = self;
    for _,val in ipairs({...}) do
        result = result ~ val;
      end
    return result;
  end
  
  function uint_64:bnot()
    return ~self;
  end
  
  function uint_64:tonumber() --[[may lose integer precision if the number is greater than 2^53]]
    return tonumber(self.m_decimal_str);
  end
  
  function uint_64:tohex(num_chars)
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

function wirebait.UInt64.fromHex(hex_str)
  --TODO: check if valid hexadecimal string
  assert(#hex_str > 0, "hexStringToUint64() requires strict positive number of bytes!");
  assert(#hex_str <= 16, "hexStringToUint64() cannot convert more thant 8 bytes to a uint value!");
  hex_str = string.format("%016s",hex_str):gsub(" ","0")
  local high_num = tonumber(string.sub(hex_str, 1,8),16);
  local num = tonumber(string.sub(hex_str, 9,16),16);
  return wirebait.UInt64.new(num, high_num);
end

  function wirebait.UInt64.max()
    return wirebait.UInt64.new(0xFFFFFFFF, 0xFFFFFFFF);
  end
  
  function wirebait.UInt64.min()
    return wirebait.UInt64.new(0, 0);
  end
--[-----------------------------------------------------------------------------------------------------------------------------------------------------------------------]]




--[----------WIRESHARK INT64----------------------------------------------------------------------------------------------------------------------------------------------]]
function wirebait.Int64.new(num, high_num)
  assert(num and type(num) == "number" and num >= 0 and num <= UINT32_MAX and num == math.floor(num), "Int64.new(num), num must be a positive 32 bit integer!");
  assert(not high_num or (type(high_num) == "number" and high_num >= 0 and high_num <= UINT32_MAX and high_num == math.floor(high_num)), "Int64.new(num, high_num): when provided, high_num must be a positive 32 bit integer!");
  --assert(num > 0 or not high_num, "num cannot be < 0 if high_num is provided!");
  local int_64 = {
    _struct_type = "Int64",
    m_low_word = num, --unsigned value in a UInt64 (I'm lazy so I will reuse as much of UInt64 as possible)
    m_high_word = high_num or 0,
  }
  
  local SIGN_MASK = 0x80000000;
  
  function int_64:__tostring()
    if int_64.m_high_word & SIGN_MASK > 0 then
      return "-" .. tostring(wirebait.UInt64.new(twosComplement(int_64.m_low_word, int_64.m_high_word)))
    end
    return tostring(wirebait.UInt64.new(int_64.m_low_word, int_64.m_high_word));
  end
  
  local function getWords(num_or_uint) --PRIVATE METHOD
    local low_word = 0;
    local high_word = 0;
    local is_negative_number = false;
    if type(num_or_uint) == "table" then
      assert(num_or_uint._struct_type == "Int64", "Argument needs to be a number or an Int64!")
      low_word = num_or_uint.m_low_word;
      high_word = num_or_uint.m_high_word;
      is_negative_number = high_word & SIGN_MASK > 0;
    else
      if num_or_uint < 0 then
        is_negative_number = true;
      end
      assert(type(num_or_uint) == "number", "Argument needs to be a number or an Int64!")
      low_word = num_or_uint & WORD_MASK;
      high_word = (num_or_uint >> 32) & WORD_MASK;
    end
    return low_word, high_word, is_negative_number;
  end
    
  function int_64.__lt(uint_or_num1, uint_or_num2)
    local low_word1, high_word1, neg1 = getWords(uint_or_num1);
    local low_word2, high_word2, neg2 = getWords(uint_or_num2);
    if neg1 ~= neg2 then
      return neg1 and true or false;
    end
    if high_word1 < high_word2 then
        return neg1 and false or true;
    else
      return neg1 and low_word1 > low_word2 or low_word1 < low_word2;
    end
  end
  
  function int_64.__eq(uint_or_num1, uint_or_num2)
    local low_word1, high_word1, neg1 = getWords(uint_or_num1);
    local low_word2, high_word2, neg2 = getWords(uint_or_num2);
    return neg1 == neg2 and low_word1 == low_word2 and high_word1 == high_word2;
  end
  
  function int_64.__le(uint_or_num1, uint_or_num2)
    return uint_or_num1 < uint_or_num2 or uint_or_num1 == uint_or_num2;
  end
  
  function int_64.__add(uint_or_num1, uint_or_num2)
    local low_word1, high_word1, neg1 = getWords(uint_or_num1);
    local low_word2, high_word2, neg2 = getWords(uint_or_num2);
    
    local function ADD(word1, word2, init_carry)
      word1 = word1 & WORD_MASK;
      word2 = word2 & WORD_MASK;
      local result = 0;
      local c = init_carry or 0;
      for i = 0,31 do
        local bw1 = (word1 >> i) & 1;
        local bw2 = (word2 >> i) & 1;
        result = result | ((bw1 ~ bw2 ~ c) << i);
        c = (bw1 + bw2 + c) > 1 and 1 or 0;
      end
      return result, c;
    end
    
    local new_low_word, carry = ADD(low_word1, low_word2);
    local new_high_word = ADD(high_word1, high_word2, carry);
    return wirebait.Int64.new(new_low_word, new_high_word);
  end
  
  function int_64.__sub(uint_or_num1, uint_or_num2)
    local low_word1, high_word1, neg1 = getWords(uint_or_num1);
    local low_word2, high_word2, neg2 = twosComplement(getWords(uint_or_num2));
    --taking advantage of the fact that A-B = A+(-B)
    return wirebait.Int64.new(low_word1, high_word1) + wirebait.Int64.new(low_word2, high_word2)
  end

  function int_64.__band(self, other) --[[bitwise AND operator (&)]]
    if type(other) == "table" and other._struct_type == "Int64" then
      local tmp = other;
      other = self;
      self = tmp;
    end
    local o_low_word = 0;
    local o_high_word = 0;
    if type(other) == "number" then
      o_low_word = other & WORD_MASK;
      o_high_word = (other >> 32) & WORD_MASK;
    elseif other._struct_type == "Int64" then
      o_low_word = other.m_low_word;
      o_high_word = other.m_high_word;
    else
      error("Cannot perform bitwise operation between Int64 and " .. type(other));
    end
    return wirebait.Int64.new(self.m_low_word & o_low_word, self.m_high_word & o_high_word)
  end
  
  function int_64:__bnot() --[[bitwise NOT operator (unary ~)]]
    return wirebait.Int64.new(~self.m_low_word & WORD_MASK, ~self.m_high_word & WORD_MASK)
  end
  
  function int_64.__bor(self, other) --[[bitwise OR operator (|)]]
    if type(other) == "table" and other._struct_type == "Int64" then
      local tmp = other;
      other = self;
      self = tmp;
    end
    local o_low_word = 0;
    local o_high_word = 0;
    if type(other) == "number" then
      o_low_word = other & WORD_MASK;
      o_high_word = (other >> 32) & WORD_MASK;
    elseif other._struct_type == "Int64" then
      o_low_word = other.m_low_word;
      o_high_word = other.m_high_word;
    else
      error("Cannot perform bitwise operation between Int64 and " .. type(other));
    end
    return wirebait.Int64.new(self.m_low_word | o_low_word, self.m_high_word | o_high_word)
  end
  
  function int_64.__bxor(self, other) --[[bitwise XOR operator (binary ~)]]
    if type(other) == "table" and other._struct_type == "Int64" then
      local tmp = other;
      other = self;
      self = tmp;
    end
    local o_low_word = 0;
    local o_high_word = 0;
    if type(other) == "number" then
      o_low_word = other & WORD_MASK;
      o_high_word = (other >> 32) & WORD_MASK;
    elseif other._struct_type == "Int64" then
      o_low_word = other.m_low_word;
      o_high_word = other.m_high_word;
    else
      error("Cannot perform bitwise operation between Int64 and " .. type(other));
    end
    return wirebait.Int64.new(self.m_low_word ~ o_low_word, self.m_high_word ~ o_high_word)
  end
  
  function int_64:__shl(shift) --[[bitwise left shift (<<)]]
    assert(type(shift) == "number" and shift == math.floor(shift), "The shift must be an integer!")
    if shift < 32 then
      local new_high_word = (self.m_low_word >> (32-shift)) + ((self.m_high_word << shift) & WORD_MASK);
      return wirebait.UInt64.new((self.m_low_word << shift) & WORD_MASK, new_high_word);
    elseif shift < 64 then
      return wirebait.UInt64.new(0, (self.m_low_word << (shift-32)) & WORD_MASK);
    else
      return wirebait.UInt64.new(0, 0);
    end
  end
  
  function int_64:__shr(shift) --[[bitwise right shift (>>)]]
    assert(type(shift) == "number" and shift == math.floor(shift), "The shift must be an integer!")
    if shift < 32 then
      local new_low_word = (self.m_low_word >> shift) + ((self.m_high_word << (32-shift)) & WORD_MASK);
      return wirebait.UInt64.new(new_low_word, self.m_high_word >> shift);
    elseif shift < 64 then
      return wirebait.Int64.new((self.m_high_word << (shift-32)) & WORD_MASK, 0);
    else
      return wirebait.Int64.new(0, 0);
    end
  end

  function int_64:lshift(shift) --[[left shift operation]]
    return self << shift;
  end
  
  function int_64:rshift(shift) --[[right shift operation]]
    return self >> shift;
  end
  
  function int_64:band(...) --[[logical AND]]
    local result = self;
    for _,val in ipairs({...}) do
        result = result & val;
      end
    return result;
  end
  
  function int_64:bor(...) --[[logical OR]]
    local result = self;
    for _,val in ipairs({...}) do
        result = result | val;
      end
    return result;
  end
  
  function int_64:bxor(...) --[[logical XOR]]
    local result = self;
    for _,val in ipairs({...}) do
        result = result ~ val;
      end
    return result;
  end
  
  function int_64:bnot()
    return ~self;
  end
  
  function int_64:tonumber() --[[may lose integer precision if the number is greater than 2^53]]
    return tonumber(self.m_decimal_str);
  end
  
  function int_64:tohex(num_chars)
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

  setmetatable(int_64, int_64)
  return int_64;
end

function wirebait.Int64.fromHex(hex_str)
  --TODO: check if valid hexadecimal string
  assert(#hex_str > 0, "hexStringToUint64() requires strict positive number of bytes!");
  assert(#hex_str <= 16, "hexStringToUint64() cannot convert more thant 8 bytes to a uint value!");
  hex_str = string.format("%016s",hex_str):gsub(" ","0")
  local high_num = tonumber(string.sub(hex_str, 1,8),16);
  local num = tonumber(string.sub(hex_str, 9,16),16);
  return wirebait.UInt64.new(num, high_num);
end

  function wirebait.Int64.max()
    return wirebait.Int64.new(0xFFFFFFFF, 0x7FFFFFFF);
  end
  
  function wirebait.Int64.min()
    return wirebait.Int64.new(0, 0x80000000);
  end
--[-----------------------------------------------------------------------------------------------------------------------------------------------------------------------]]

















--[----------WIRESHARK PROTO----------------------------------------------------------------------------------------------------------------------------------------------]]
--[[ Equivalent of [wireshark Proto](https://wiki.wireshark.org/LuaAPI/Proto#Proto) ]]
function wirebait.Proto.new(abbr, description)
  assert(description and abbr, "Proto argument should not be nil!")
  local proto = {
    _struct_type = "Proto";
    m_description = description,
    m_abbr = abbr,
    fields = {}, --protofields
    dissector = {}, --dissection function
    name = description --ws api
  }

  assert(wirebait.state.proto == nil, "Wirebait currenlty only support 1 proto per dissector file!");
  wirebait.state.proto = proto;
  return proto;
end
--[-----------------------------------------------------------------------------------------------------------------------------------------------------------------------]]


--[----------WIRESHARK PROTOFIELD-----------------------------------------------------------------------------------------------------------------------------------------]]
--[[ Equivalent of [wireshark ProtoField](https://wiki.wireshark.org/LuaAPI/Proto#ProtoField) ]]
function wirebait.ProtoField.new(name, abbr, ftype, value_string, fbase, mask, desc)
  assert(name and abbr and ftype, "ProtoField name, abbr, and type must not be nil!");
  assert(type(name) == "string" and type(abbr) == "string" and type(ftype) == "string", "ProtoField name, abbr, and type must be strings!");
  assert(not fbase or type(fbase) == "number" and fbase == math.floor(fbase), "The optional ProtoField base must to be an integer!");
  assert(not mask or type(mask) == "number" and mask == math.floor(mask), "The optional ProtoField mask must to be an integer!");
  assert(not value_string or type(value_string) == "table", "The optional ProtoField valuestring must be a table!");
  local protofield = {
    _struct_type = "ProtoField";
    m_name = name;
    m_abbr = abbr;
    m_type = ftype;
    m_value_string = value_string; --[[table of values and their corresponding string value ]]
    m_base = fbase; --[[determines what base is used to display an treeitem value]]
    m_mask = mask; --[[mask only works for types that are by definition <= 8 bytes]]
    m_description = desc; --[[The description is a text displayed in the Wireshark GUI when the field is selected. Irrelevant in wirebait]]
  }

  function protofield:getValueFromBuffer(buffer)
    local extractValueFuncByType = {
      uint8   = function (buf) return buf:uint() & (mask or 0xFF) end,
      uint16  = function (buf) return buf:uint() & (mask or 0xFFFF) end,
      uint24  = function (buf) return buf:uint() & (mask or 0xFFFFFF) end,
      uint32  = function (buf) return buf:uint() & (mask or 0xFFFFFFFF) end,
      uint64  = function (buf) assert(not mask, "mask not supported yet for uint64"); return buf:uint64() end,
      int8   = function (buf) return buf:int(mask) end, --[[mask is provided here because it needs to be applied on the raw value and not on the decoded int]]
      int16  = function (buf) return buf:int(mask) end,
      int24  = function (buf) return buf:int(mask) end,
      int32  = function (buf) return buf:int(mask) end,
      int64  = function (buf) return buf:int64(mask) end,
      stringz = function (buf) return buf:stringz() end,
      bool    = function (buf) return buf:uint64() > 0 end
    };

    local func = extractValueFuncByType[self.m_type];
    assert(func, "Unknown protofield type '" .. self.m_type .. "'!")
    return func(buffer);
  end

  function protofield:getMaskPrefix(buffer)
    if not self.m_mask then
      return "";
    end
    local value = self:getValueFromBuffer(buffer);
    local str_value = tostring(value);
    local current_bit = 1;
    local displayed_masked_value = "";
    while current_bit <= self.m_mask do
      if self.m_mask & current_bit == 0 then
        displayed_masked_value = displayed_masked_value .. ".";
      else 
        if value & current_bit > 0 then
          displayed_masked_value = displayed_masked_value .. "1";
        else
          displayed_masked_value = displayed_masked_value .. "0";
        end
      end
      current_bit = current_bit << 1;
    end
    displayed_masked_value = string.format("%".. buffer:len()*8 .."s", displayed_masked_value):gsub(" ",".");
    str_value = displayed_masked_value .. " = "; -- .. str_value;
    return str_value;
  end

  function protofield:getDisplayValueFromBuffer(buffer)
    local value = self:getValueFromBuffer(buffer);
    local str_value = tostring(value);
    local value_string = nil;
    if self.m_value_string and self.m_value_string[value] then
      value_string = self.m_value_string[value];
    end
    if self.m_base == wirebait.base.HEX then
      if value_string then 
        str_value = value_string .. " (0x" .. buffer:bytes() .. ")";
      else
        str_value = "0x" .. buffer:bytes();
      end
    elseif self.m_base == wirebait.base.HEX_DEC then 
      if value_string then 
        str_value =  value_string .. " (0x" .. buffer:bytes() .. ")";
      else
        str_value = "0x" .. buffer:bytes() .. " (" .. str_value .. ")";
      end
    elseif self.m_base == wirebait.base.DEC_HEX then 
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

function wirebait.ProtoField.string(abbr, name, display, desc)            return wirebait.ProtoField.new(name, abbr, "string", nil, display, nil, desc) end
function wirebait.ProtoField.stringz(abbr, name, display, desc)           return wirebait.ProtoField.new(name, abbr, "stringz", nil, display, nil, desc) end
function wirebait.ProtoField.uint8(abbr, name, fbase, value_string, ...)  return wirebait.ProtoField.new(name, abbr, "uint8", value_string, fbase, ...) end
function wirebait.ProtoField.uint16(abbr, name, fbase, value_string, ...) return wirebait.ProtoField.new(name, abbr, "uint16", value_string, fbase, ...) end
function wirebait.ProtoField.uint24(abbr, name, fbase, value_string, ...) return wirebait.ProtoField.new(name, abbr, "uint24", value_string, fbase, ...) end
function wirebait.ProtoField.uint32(abbr, name, fbase, value_string, ...) return wirebait.ProtoField.new(name, abbr, "uint32", value_string, fbase, ...) end
function wirebait.ProtoField.uint64(abbr, name, fbase, value_string, ...) return wirebait.ProtoField.new(name, abbr, "uint64", value_string, fbase, ...) end
function wirebait.ProtoField.int8(abbr, name, fbase, value_string, ...)  return wirebait.ProtoField.new(name, abbr, "int8", value_string, fbase, ...) end
function wirebait.ProtoField.int16(abbr, name, fbase, value_string, ...) return wirebait.ProtoField.new(name, abbr, "int16", value_string, fbase, ...) end
function wirebait.ProtoField.int24(abbr, name, fbase, value_string, ...) return wirebait.ProtoField.new(name, abbr, "int24", value_string, fbase, ...) end
function wirebait.ProtoField.int32(abbr, name, fbase, value_string, ...) return wirebait.ProtoField.new(name, abbr, "int32", value_string, fbase, ...) end
function wirebait.ProtoField.int64(abbr, name, fbase, value_string, ...) return wirebait.ProtoField.new(name, abbr, "int64", value_string, fbase, ...) end
function wirebait.ProtoField.bool(abbr, name, fbase, value_string, ...)   return wirebait.ProtoField.new(name, abbr, "bool", value_string, fbase, ...) end
--[-----------------------------------------------------------------------------------------------------------------------------------------------------------------------]]


--[----------WIRESHARK TREEITEM-------------------------------------------------------------------------------------------------------------------------------------------]]
--[[ Equivalent of [wireshark treeitem](https://wiki.wireshark.org/LuaAPI/TreeItem) ]]
function wirebait.treeitem.new(protofield, buffer, parent) 
  local treeitem = {
    m_protofield = protofield,
    m_depth = 0,
    m_buffer = buffer,
    m_text = nil
  }
  if parent then
    treeitem.m_depth = parent.m_depth + 1;
  end

  local function prefix(depth)
    assert(depth >= 0, "Tree depth cannot be negative (" .. depth .. ")!");
    return depth == 0 and "" or string.rep(" ", 3*(depth - 1)) .. "└─ ";
  end

  --[[ Private function adding a proto to the provided treeitem ]]
  local function addProto(tree, proto, buffer_or_value, texts)
    assert(buffer_or_value, "When adding a protofield, either a tvb range, or a value must be provided!");
    if type(buffer_or_value) == "string" or type(buffer_or_value) == "number" then
      --[[if no buffer provided, value will be appended to the treeitem, and no bytes will be highlighted]]
      value = buffer_or_value;
    else
      --[[if buffer is provided, value maybe provided, in which case it will override the value parsed from the buffer]]
      buffer = buffer_or_value
      assert(buffer._struct_type == "buffer", "Buffer expected but got another userdata type!")
      if #texts > 0 then
        value = texts[1] --might be nil
        table.remove(texts,1); --removing value from the texts array
      end
      if #texts == 0 then
        texts = nil
      end
    end
    assert(buffer or value, "Bug in this function, buffer and value cannot be both nil!");

    local child_tree = wirebait.treeitem.new(protofield, buffer, tree);
    if texts then --texts override the value displayed in the tree including the header defined in the protofield
      child_tree.m_text = tostring(prefix(tree.m_depth) .. table.concat(texts, " "));
    else
      child_tree.m_text = tostring(prefix(tree.m_depth) .. proto.m_description);
    end
    return child_tree;
  end

  --[[ Private function adding a protofield to the provided treeitem ]]
  local function addProtoField(tree, protofield, buffer_or_value, texts)
    assert(buffer_or_value, "When adding a protofield, either a tvb range, or a value must be provided!");
    local value = nil;
    if type(buffer_or_value) == "string" or type(buffer_or_value) == "number" then
      --[[if no buffer provided, value will be appended to the treeitem, and no bytes will be highlighted]]
      value = buffer_or_value;
    else
      --[[if buffer is provided, value maybe provided, in which case it will override the value parsed from the buffer]]
      buffer = buffer_or_value
      assert(buffer._struct_type == "buffer", "Buffer expected but got another userdata type!")
      if texts then
        if type(texts) == "table" then
          if #texts > 0 then
            value = texts[1] --might be nil
            table.remove(texts,1); --removing value from the texts array
          end
          if #texts == 0 then
            texts = nil;
          end
        else
          value = texts;
          texts = nil;
        end
      end
    end
    assert(buffer or value, "Bug in this function, buffer and value cannot be both nil!");

    local child_tree = wirebait.treeitem.new(protofield, buffer, tree);
    if texts then --texts override the value displayed in the tree including the header defined in the protofield
      child_tree.m_text = tostring(prefix(tree.m_depth) .. table.concat(texts, " "));
    else
      local printed_value = tostring(value or protofield:getDisplayValueFromBuffer(buffer)) -- buffer(0, size):bytes()
      child_tree.m_text = tostring(prefix(tree.m_depth) .. protofield:getMaskPrefix(buffer) .. protofield.m_name .. ": " .. printed_value); --TODO review the or buffer:len
    end
    return child_tree;
  end

  --[[ Private function adding a treeitem to the provided treeitem, without an associated protofield ]]
  --[[ Very (like VERY) lazy, and hacky, and poor logic but it works ]]
  -- TODO: clean this up!
  local function addTreeItem(tree, buffer, value, texts)
    local protofield = nil;
    table.insert(texts, 1, value); --insert value in first position
    table.insert(texts, 1, "");
    return addProtoField(tree, protofield, buffer, texts)
  end

  --[[ Checks if a protofield was registered]]
  local function checkProtofieldRegistered(protofield)
    for k, v in pairs(wirebait.state.proto.fields) do
      if protofield == v then
        return true;
      end
    end
    return false;
  end

  --[[TODO: add uni tests]]
  function treeitem:add(proto_or_protofield_or_buffer, buffer, value, ...)
    if proto_or_protofield_or_buffer._struct_type == "ProtoField" and not checkProtofieldRegistered(proto_or_protofield_or_buffer) then
      print("ERROR: Protofield '" .. proto_or_protofield_or_buffer.m_name .. "' was not registered!")
      os.exit()
    end
    local new_treeitem = nil;
    if proto_or_protofield_or_buffer._struct_type == "Proto" then
      new_treeitem = addProto(self, proto_or_protofield_or_buffer, buffer, {value, ...});
    elseif proto_or_protofield_or_buffer._struct_type == "ProtoField" then
      new_treeitem = addProtoField(self, proto_or_protofield_or_buffer, buffer, {value, ...});
    elseif proto_or_protofield_or_buffer._struct_type == "buffer" then --adding a tree item without protofield
      new_treeitem = addTreeItem(self, proto_or_protofield_or_buffer, buffer, {value, ...});
    else
      error("First argument in treeitem:add() should be a Proto or Profofield");
    end
    table.insert(wirebait.state.packet_info.treeitems_array, new_treeitem);
    return new_treeitem;
  end

  --[[TODO: add unit tests]]
  function treeitem:add_le(proto_or_protofield_or_buffer, buffer, value, ...)
    assert(proto_or_protofield_or_buffer._struct_type == "buffer" or buffer._struct_type == "buffer", "Expecting a tvbrange somewhere in the arguments!")
    if proto_or_protofield_or_buffer._struct_type == "buffer" then
      proto_or_protofield_or_buffer = wirebait.buffer.new(proto_or_protofield_or_buffer:swapped_bytes());
    else
      buffer = wirebait.buffer.new(buffer:swapped_bytes());
    end
    return self:add(proto_or_protofield_or_buffer, buffer, value, ...)
  end

  function treeitem:set_text(text)
    text:gsub("\n", " ");
    self.m_text = text
  end

  function treeitem:append_text(text)
    text:gsub("\n", " ");
    self.m_text = self.m_text .. text
  end

  function treeitem:set_len(length)
    io.write("WIREBAIT WARNING: treeitem:set_length() is not supported by wirebait yet.");
  end

  function treeitem:set_generated()
    io.write("WIREBAIT WARNING: treeitem:set_generated() is not supported by wirebait yet.");
  end

  function treeitem:set_hidden()
    io.write("WIREBAIT WARNING: treeitem:set_hidden() is not supported by wirebait yet.");
  end

  function treeitem:set_expert_flags()
    io.write("WIREBAIT WARNING: treeitem:set_expert_flags() is not supported by wirebait yet.");
  end

  function treeitem:set_expert_info()
    io.write("WIREBAIT WARNING: treeitem:set_expert_info() is not supported by wirebait yet.");
  end

  return treeitem;
end
--[-----------------------------------------------------------------------------------------------------------------------------------------------------------------------]]


--[----------WIRESHARK BYTEARRAY/TVB/TVBRANGE-----------------------------------------------------------------------------------------------------------------------------]]
--[[ Equivalent of [wireshark ByteArray](https://wiki.wireshark.org/LuaAPI/ByteArray), [wireshark Tvb](https://wiki.wireshark.org/LuaAPI/Tvb#Tvb), and [wireshark TvbRange](https://wiki.wireshark.org/LuaAPI/Tvb#TvbRange) ]]
function wirebait.buffer.new(data_as_hex_string)
  assert(type(data_as_hex_string) == 'string', "Buffer should be based on an hexadecimal string!")
  data_as_hex_string = data_as_hex_string:gsub("%s+","") --removing white spaces
  assert(not data_as_hex_string:find('%X'), "String should be hexadecimal!")
  assert(string.len(data_as_hex_string) % 2 == 0, "String has its last byte cut in half!")

  local buffer = {
    _struct_type = "buffer",
    m_data_as_hex_str = data_as_hex_string:upper(),
  }
  local escape_replacements = {["\0"]="\\0", ["\t"]="\\t", ["\n"]="\\n", ["\r"]="\\r", }

  function buffer:len()
    return math.floor(string.len(self.m_data_as_hex_str)/2);
  end

  function buffer:uint()
    assert(self:len() <= 4, "tvbrange:uint() cannot decode more than 4 bytes! (len = " .. self:len() .. ")");
    return hexStringToUint32(self:bytes());
  end

  function buffer:uint64()
    assert(self:len() <= 8, "tvbrange:uint64() cannot decode more than 8 bytes! (len = " .. self:len() .. ")");
    return wirebait.UInt64.fromHex(self:bytes());
  end;

  function buffer:le_uint()
    assert(self:len() <= 4, "tvbrange:le_uint() cannot decode more than 4 bytes! (len = " .. self:len() .. ")");
    return hexStringToUint32(self:swapped_bytes());
  end

  function buffer:le_uint64()
    assert(self:len() <= 8, "tvbrange:le_uint64() cannot decode more than 8 bytes! (len = " .. self:len() .. ")");
    return wirebait.UInt64.fromHex(self:swapped_bytes());
  end;

  function buffer:int(mask)
    local size = self:len();
    assert(size == 1 or size == 2 or size == 4, "Buffer must be 1, 2, or 4 bytes long for buffer:int() to work. (Buffer size: " .. self:len() ..")");
    local uint = self:uint();
    if mask then
      uint = uint & mask;
    end
    local sign_mask=tonumber("80" .. string.rep("00", size-1), 16);
    if uint & sign_mask > 0 then --we're dealing with a negative number
      local val_mask=tonumber("7F" .. string.rep("FF", size-1), 16);
      local val = -((~uint & val_mask) + 1);
      return val;
    else --we are dealing with a positive number
      return uint;
    end
  end

  function buffer:le_int(mask)
    local size = self:len();
    assert(size == 1 or size == 2 or size == 4, "Buffer must be 1, 2, or 4 bytes long for buffer:le_int() to work. (Buffer size: " .. self:len() ..")");
    return wirebait.buffer.new(self:swapped_bytes()):int(mask);
  end

  function buffer:int64(mask)
    local size = self:len();
    assert(size == 1 or size == 2 or size == 4 or size == 8, "Buffer must be 1, 2, 4, or 8 bytes long for buffer:int() to work. (Buffer size: " .. self:len() ..")");
    if size <= 4 then
      return self:int();
    elseif self(0,1):uint() & 0x80 == 0 then --positive int
      return self:uint64();
    else --[[when dealing with really large uint64, uint64() returns float instead of integers, which means I can't use bitwise operations. To get around that I treat
      the 64 bit int as 2 separate words on which I perform the bitwise operation, then I "reassemble" the int]]
      local first_word_raw = self(0,4):uint();
      local second_word_raw = self(4,4):uint();
      if mask then
        first_word_raw = first_word_raw & (mask >> 8);
        second_word_raw = second_word_raw & (mask & 0x00000000FFFFFFFF);
      end
      local first_word_val = ~first_word_raw & 0x7FFFFFFF;
      local second_word_val = ~second_word_raw & 0xFFFFFFFF;
      local result = -(math.floor(first_word_val * 16^8) + second_word_val + 1)
      return result;
    end
  end

  function buffer:le_int64(mask)
    local size = self:len();
    assert(size == 1 or size == 2 or size == 4 or size == 8, "Buffer must be 1, 2, 4, or 8 bytes long for buffer:le_int() to work. (Buffer size: " .. self:len() ..")");
    return wirebait.buffer.new(self:swapped_bytes()):int64(mask);
  end

  function buffer:float()
    local size = self:len();
    assert(size == 4 or size == 8, "Buffer must be 4 or 8 bytes long for buffer:float() to work. (Buffer size: " .. self:len() ..")");
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
      local exp = (uint & exponent_mask) >> bit_len;
      local fraction= 1;
      for i=1,bit_len do
        local bit_mask = 1 << (bit_len-i); --looking at one bit at a time
        if bit_mask & uint > 0 then
          fraction = fraction + math.pow(2,-i)
        end
      end
      local absolute_value = fraction * math.pow(2, exp -127);
      local sign = uint & 0x80000000 > 0 and -1 or 1;
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
      local exp = (word1 & exponent_mask) >> bit_len1;
      local fraction= 1;
      for i=1,bit_len1 do --[[starting to calculate fraction with word1]]
        local bit_mask = 1 << (bit_len1-i); --looking at one bit at a time
        if bit_mask & word1 > 0 then
          fraction = fraction + math.pow(2,-i)
        end
      end
      local bit_len2 = 32; --[[finishing to calculate fraction with word2]]
      for i=1,bit_len2 do
        local bit_mask = 1 << (bit_len2-i); --looking at one bit at a time
        if bit_mask & word2 > 0 then
          fraction = fraction + math.pow(2,-i-bit_len1)
        end
      end
      local absolute_value = fraction * math.pow(2, exp - 1023);
      local sign = word1 & 0x80000000 > 0 and -1 or 1;
      return sign * absolute_value;
    end
  end

  function buffer:le_float()
    local size = self:len();
    assert(size == 4 or size == 8, "Buffer must be 4 or 8 bytes long for buffer:le_float() to work. (Buffer size: " .. self:len() ..")");
    return wirebait.buffer.new(self:swapped_bytes()):float();
  end

  function buffer:ipv4()
    assert(self:len() == 4, "Buffer must by 4 bytes long for buffer:ipv4() to work. (Buffer size: " .. self:len() ..")");
    return printIP(self:int());
  end

  function buffer:le_ipv4()
    assert(self:len() == 4, "Buffer must by 4 bytes long for buffer:le_ipv4() to work. (Buffer size: " .. self:len() ..")");
    return printIP(self:le_int());
  end

  function buffer:eth()
    assert(self:len() == 6, "Buffer must by 6 bytes long for buffer:eth() to work. (Buffer size: " .. self:len() ..")");
    local eth_addr = "";
    for i=1,self:len() do
      local sep = i == 1 and "" or ":";
      eth_addr = eth_addr .. sep .. self(i-1,1):bytes();
    end
    return eth_addr;
  end

  function buffer:string()
    local str = ""
    for i=1,self:len() do
      local byte_ = self.m_data_as_hex_str:sub(2*i-1,2*i)
      str = str .. string.char(tonumber(byte_, 16))
    end
    str = string.gsub(str, ".", escape_replacements) --replacing escaped characters that characters that would cause io.write() or print() to mess up is they were interpreted
    return str
  end

  function buffer:stringz()
    local str = ""
    for i=1,self:len()-1 do
      local byte_ = self.m_data_as_hex_str:sub(2*i-1,2*i)
      if byte_ == '00' then --null char termination
        return str
      end
      str = str .. string.char(tonumber(byte_, 16))
    end
    str = string.gsub(str, ".", escape_replacements) --replacing escaped characters that characters that would cause io.write() or print() to mess up is they were interpreted
    return str
  end

  --[[TODO: this is not utf-16]]
  function buffer:ustring()
    return self:string();
  end

  --[[TODO: this is not utf-16]]
  function buffer:ustringz()
    return self:stringz();
  end

  function buffer:le_ustring()
    local be_hex_str = swapBytes(self:bytes());
    return wirebait.buffer.new(be_hex_str):ustring();
  end

  function buffer:le_ustringz()
    local be_hex_str = swapBytes(self:bytes());
    return wirebait.buffer.new(be_hex_str):ustringz();
  end

  function buffer:bitfield(offset, length)
    offset = offset or 0;
    length = length or 1;
    assert(length <= 64, "Since bitfield() returns a uint64 of the bitfield, length must be <= 64 bits! (length: " .. length .. ")")
    local byte_offset = math.floor(offset/8);
    local byte_size = math.ceil((offset+length)/8) - byte_offset;
    local left_bits_count = offset % 8;
    local right_bits_count = (byte_size + byte_offset)*8 - (offset+length);

    local bit_mask = tonumber(string.rep("FF", byte_size), 16);
    for i=1,left_bits_count do 
      bit_mask = bit_mask ~ (1 << (8*byte_size - i)); -- left bits need to be masked out of the value
    end

    if length > 56 then -- past 56 bits, lua starts to interpret numbers as floats
      local first_word_val = self(0,4):uint();
      local second_word_val = self(4, 4):uint() >> right_bits_count;
      bit_mask = bit_mask >> 32;
      first_word_val = first_word_val & bit_mask;
      local result = math.floor((first_word_val << (32 - right_bits_count)) + second_word_val)
      return result;
    else
      local uint_val = self(byte_offset, byte_size):uint64();
      return (uint_val & bit_mask) >> right_bits_count;
    end
  end

--  function buffer:bytes()
--    return self.m_data_as_hex_str;
--  end

  function buffer:bytes()
    return self.m_data_as_hex_str;
  end

  function buffer:swapped_bytes()
    return swapBytes(self.m_data_as_hex_str);
  end

  function buffer:__call(start, length) --allows buffer to be called as a function 
    assert(start >= 0, "Start position should be positive positive!");
    length = length or self:len() - start; --add unit test for the case where no length was provided
    assert(length >= 0, "Length should be positive!");
    assert(start + length <= self:len(), "Index get out of bounds!")
    return wirebait.buffer.new(string.sub(self.m_data_as_hex_str,2*start+1, 2*(start+length)))            
  end

  function buffer:__tostring()
    return "[buffer: 0x" .. self.m_data_as_hex_str .. "]";
  end

  setmetatable(buffer, buffer)

  return buffer;
end
--[-----------------------------------------------------------------------------------------------------------------------------------------------------------------------]]


--[----------WIRESHARK DISSECTOR TABLE------------------------------------------------------------------------------------------------------------------------------------]]
local function newDissectorTable()
  dissector_table = { 
    udp = { port = {} },
    tcp = { port = {} },
  }

  local function newPortTable()
    port_table = {}

    function port_table:add(port, proto_handle)
      local port_number = tonumber(port);
      assert(port_number >= 0 and port_number <= 65535, "A port must be between 0 and 65535!")
      self[port_number] = proto_handle;
    end

    return port_table;
  end

  dissector_table.udp.port = newPortTable();

  function dissector_table.get(path)
    local obj = dissector_table;
    path:gsub("%a+", function(split_path) obj = obj[split_path] end)
    return obj;
  end

  return dissector_table;
end
--[-----------------------------------------------------------------------------------------------------------------------------------------------------------------------]]

--[----------WIRESHARK DISSECTOR TABLE------------------------------------------------------------------------------------------------------------------------------------]]
local function newPacketInfo()
  local packet_info = {
    cols = { 
      protocol = nil
    },
    treeitems_array = {}
  }
  return packet_info;
end

--[----------PCAP READING LOGIC-------------------------------------------------------------------------------------------------------------------------------------------]]
--[[ Data structure holding an ethernet packet, which is used by wirebait to hold packets read from pcap files 
     At initialization, all the member of the struct are set to nil, which leaves the structure actually empty. The point here
     is that you can visualize what the struct would look like once populated]]
function wirebait.packet.new (packet_buffer)
  local packet = {
    ethernet = {
      dst_mac = nil, --string in hex format e.g. "EC086B703682" (which would correspond to the mac address ec:08:6b:70:36:82
      src_mac = nil,
      type = nil, --type as unsigned int, e.g. 0x0800 for IPV4
      ipv4 = {
        protocol = nil, --protocol as unsigned int, e.g. 0x06 for TCP
        dst_ip = nil, -- uint32 little endian
        src_ip = nil, -- uint32 little endian
        udp = {
          src_port = nil,
          dst_port = nil,
          data = nil,
        },
        tcp = {
          src_port = nil,
          dst_port = nil,
          data = nil,
        },
        other_data = nil, -- exist if pkt is not tcp nor udp
      }, 
      other_data = nil -- exist if pkt is not ip
    }
  }
  --assert(packet_buffer:len() > 14, "Invalid packet " .. packet_buffer .. ". It is too small!");
  --[[Ethernet layer parsing]]
  packet.ethernet.dst_mac = packet_buffer(0,6):bytes();
  packet.ethernet.src_mac = packet_buffer(6,6):bytes();
  packet.ethernet.type = packet_buffer(12,2):uint(); --e.g 0x0800 for IP
  if packet.ethernet.type ~= PROTOCOL_TYPES.IPV4 then
    packet.ethernet.other = packet_buffer(14,packet_buffer:len() - 14);
  else
    --[[IPV4 layer parsing]]
    packet.ethernet.ipv4.protocol = packet_buffer(23,1):uint();
    packet.ethernet.ipv4.src_ip = packet_buffer(26,4):uint();
    packet.ethernet.ipv4.dst_ip = packet_buffer(30,4):uint();

    --[[UDP layer parsing]]
    if packet.ethernet.ipv4.protocol == PROTOCOL_TYPES.UDP then
      packet.ethernet.ipv4.udp.src_port = packet_buffer(34,2):uint();
      packet.ethernet.ipv4.udp.dst_port = packet_buffer(36,2):uint();
      assert(packet_buffer:len() >= 42, "Packet buffer is of invalid size!")
      packet.ethernet.ipv4.udp.data = packet_buffer(42,packet_buffer:len() - 42);
    elseif packet.ethernet.ipv4.protocol == PROTOCOL_TYPES.TCP then
      --[[TCP layer parsing]]
      packet.ethernet.ipv4.tcp.src_port = packet_buffer(34,2):uint();
      packet.ethernet.ipv4.tcp.dst_port = packet_buffer(36,2):uint();
      -- for Lua 5.3 and above
      local tcp_hdr_len = 4 * ((packet_buffer(46,1):uint() & 0xF0) >> 4);
      -- for Lua 5.2 and below
      --local tcp_hdr_len = bit32.arshift(bit32.band(packet_buffer(46,1):uint(), 0xF0)) * 4;
      local tcp_payload_start_index = 34 + tcp_hdr_len;
      assert(packet_buffer:len() >= tcp_payload_start_index, "Packet buffer is of invalid size!")
      --if packet_buffer:len() > tcp_payload_start_index then
      packet.ethernet.ipv4.tcp.data = packet_buffer(tcp_payload_start_index, packet_buffer:len() - tcp_payload_start_index);
    else
      --[[Unknown transport layer]]
      packet.ethernet.ipv4.other = packet_buffer(14,packet_buffer:len() - 14);
    end
  end

  function packet:info()
    if self.ethernet.type == PROTOCOL_TYPES.IPV4 then
      if self.ethernet.ipv4.protocol == PROTOCOL_TYPES.UDP then
        return "UDP packet from " .. printIP(self.ethernet.ipv4.src_ip) .. ":" ..  self.ethernet.ipv4.udp.src_port 
        .. " to " .. printIP(self.ethernet.ipv4.dst_ip) .. ":" ..  self.ethernet.ipv4.udp.dst_port --.. "\n" .. print_bytes(self.ethernet.ipv4.udp.data, 2,8)
        --.. ". Payload: " .. tostring(self.ethernet.ipv4.udp.data);
      elseif self.ethernet.ipv4.protocol == PROTOCOL_TYPES.TCP then
        return "TCP packet from " .. printIP(self.ethernet.ipv4.src_ip) .. ":" ..  self.ethernet.ipv4.tcp.src_port 
        .. " to " .. printIP(self.ethernet.ipv4.dst_ip) .. ":" ..  self.ethernet.ipv4.tcp.dst_port --.. "\n" .. print_bytes(self.ethernet.ipv4.tcp.data, 2,8)
        --.. ". Payload: " .. tostring(self.ethernet.ipv4.tcp.data);
      else
        --[[Unknown transport layer]]
        return "IPv4 packet from " .. self.ethernet.ipv4.src_ip .. " to " .. self.ethernet.ipv4.dst_ip;
      end
    else
      return "Ethernet packet (non ipv4)";
    end
  end

  function packet:getIPProtocol()
    return self.ethernet.ipv4.protocol;
  end

  function packet:getSrcPort()
    local ip_proto = self:getIPProtocol();
    if ip_proto == PROTOCOL_TYPES.UDP then
      return self.ethernet.ipv4.udp.src_port
    elseif ip_proto == PROTOCOL_TYPES.TCP then
      return self.ethernet.ipv4.tcp.src_port
    else
      error("Packet currently only support getSrcPort() for IP/UDP and IP/TCP protocols!")
    end
  end

  function packet:getDstPort()
    local ip_proto = self:getIPProtocol();
    if ip_proto == PROTOCOL_TYPES.UDP then
      return self.ethernet.ipv4.udp.dst_port
    elseif ip_proto == PROTOCOL_TYPES.TCP then
      return self.ethernet.ipv4.tcp.dst_port
    else
      error("Packet currently only support getDstPort() for IP/UDP and IP/TCP protocols!")
    end
  end

  return packet;
end

function wirebait.pcap_reader.new(filepath)
  local pcap_reader = {
    m_file = io.open(filepath, "rb"), --b is for binary, and is only there for windows
  }
  --[[Performing various checks before reading the packet data]]
  assert(pcap_reader.m_file, "File at '" .. filepath .. "' not found!");
  local global_header_buf = wirebait.buffer.new(readFileAsHex(pcap_reader.m_file, 24));
  assert(global_header_buf:len() == 24, "Pcap file is not large enough to contain a full global header.");
  assert(global_header_buf(0,4):bytes() == "D4C3B2A1", "Pcap file with magic number '" .. global_header_buf(0,4):bytes() .. "' is not supported! (Note that pcapng file are not supported either)"); 

  --[[Reading pcap file and returning the next ethernet frame]]
  function pcap_reader:getNextEthernetFrame()
    --Reading pcap packet header (this is not part of the actual ethernet frame)
    local pcap_hdr_buffer = wirebait.buffer.new(readFileAsHex(self.m_file, 16));
    if pcap_hdr_buffer:len() < 16 then -- this does not handle live capture
      return nil;
    end
    local packet_length = pcap_hdr_buffer(8,4):le_uint();
    local packet_buffer = wirebait.buffer.new(readFileAsHex(self.m_file, packet_length));
    if packet_buffer:len() < packet_length then -- this does not handle live capture
      return nil;
    end
    assert(packet_buffer:len() > 14, "Unexpected packet in pcap! This frame cannot be an ethernet frame! (frame: " .. tostring(packet_buffer) .. ")");
    local ethernet_frame = wirebait.packet.new(packet_buffer);
    return ethernet_frame;
  end
  return pcap_reader;
end

function wirebait.plugin_tester.new(options_table) --[[options_table uses named arguments]] --TODO: document a comprehensive list of named arguments
  options_table = options_table or {};
  _WIREBAIT_ON_ = true; --globally scoped on purpose
  local plugin_tester = {
    m_dissector_filepath = options_table.dissector_filepath or arg[0], --if dissector_filepath is not provided, takes the path to the script that was launched
    m_only_show_dissected_packets = options_table.only_show_dissected_packets or false
  };

  --Setting up the environment before invoking dofile() on the dissector script
  wirebait.state.dissector_table = newDissectorTable();
  UInt64 = wirebait.UInt64;
  Int64 = wirebait.Int64;
  base = wirebait.base;
  Proto = wirebait.Proto.new;
  ProtoField = wirebait.ProtoField;
  DissectorTable = wirebait.state.dissector_table;
  dofile(plugin_tester.m_dissector_filepath);

  local function formatBytesInArray(buffer, bytes_per_col, cols_count) --[[returns formatted bytes in an array of lines of bytes. --TODO: clean this up]]
    if buffer:len() == 0 then
      return {"<empty>"}
    end
    bytes_per_col = bytes_per_col or 8;
    cols_count = cols_count or 2;
    local array_of_lines = {};
    local str = "";
    for i=1,buffer:len() do
      str = str .. " " .. buffer(i-1,1):bytes();
      if i % bytes_per_col == 0 then
        if i % (cols_count * bytes_per_col) == 0 then
          table.insert(array_of_lines, str)
          str = ""
        else
          str = str .. "  ";
        end
      end
    end
    if #str > 0 then
      table.insert(array_of_lines, str)
    end
    return array_of_lines;
  end

  function plugin_tester:dissectPcap(pcap_filepath)
    assert(pcap_filepath, "plugin_tester:dissectPcap() requires 1 argument: a path to a pcap file!");
    local pcap_reader = wirebait.pcap_reader.new(pcap_filepath)
    local packet_no = 1;
    repeat
      local packet = pcap_reader:getNextEthernetFrame()
      if packet then
        wirebait.state.packet_info = newPacketInfo();
        local buffer = packet.ethernet.ipv4.udp.data or packet.ethernet.ipv4.tcp.data;
        if buffer then
          local root_tree = wirebait.treeitem.new(buffer);
          local proto_handle = nil;
          if packet:getIPProtocol() == PROTOCOL_TYPES.UDP then
            proto_handle = wirebait.state.dissector_table.udp.port[packet:getSrcPort()] or wirebait.state.dissector_table.udp.port[packet:getDstPort()];
          else 
            assert(packet:getIPProtocol() == PROTOCOL_TYPES.TCP)
            proto_handle = wirebait.state.dissector_table.tcp.port[packet:getSrcPort()] or wirebait.state.dissector_table.tcp.port[packet:getDstPort()];
          end
          if proto_handle or not self.m_only_show_dissected_packets then
            io.write("------------------------------------------------------------------------------------------------------------------------------[[\n");
            io.write("Frame# " .. packet_no .. ": " .. packet:info() .. "\n");
            if proto_handle then
              assert(proto_handle == wirebait.state.proto, "The proto handler found in the dissector table should match the proto handle stored in wirebait.state.proto!")
              proto_handle.dissector(buffer, wirebait.state.packet_info, root_tree);
              local packet_bytes_lines = formatBytesInArray(buffer);
              local treeitems_array = wirebait.state.packet_info.treeitems_array;
              local size = math.max(#packet_bytes_lines, #treeitems_array);
              for i=1,size do
                local bytes_str = string.format("%-48s",packet_bytes_lines[i] or "")
                local treeitem_str = treeitems_array[i] and treeitems_array[i].m_text or "";
                io.write("\t" .. bytes_str .. "\t|\t" .. treeitem_str .. "\n");
              end
            end
            io.write("]]------------------------------------------------------------------------------------------------------------------------------\n\n\n");
          end
        end
      end
      packet_no = packet_no + 1;
    until packet == nil
  end

  function plugin_tester:dissectHexData(hex_data)
    io.write("------------------------------------------------------------------------------------------------------------------------------[[\n");
    io.write("Dissecting hexadecimal data (no pcap provided)\n");
    local buffer = wirebait.buffer.new(hex_data:gsub(" ",""));
    local root_tree = wirebait.treeitem.new(buffer);
    wirebait.state.packet_info = newPacketInfo();
    assert(wirebait.state.proto, "It doens't seem like any proto was registered!")
    wirebait.state.proto.dissector(buffer, wirebait.state.packet_info, root_tree);
    local packet_bytes_lines = formatBytesInArray(buffer);
    local treeitems_array = wirebait.state.packet_info.treeitems_array;
    local size = math.max(#packet_bytes_lines, #treeitems_array);
    for i=1,size do
      local bytes_str = string.format("%-48s",packet_bytes_lines[i] or "")
      local treeitem_str = treeitems_array[i] and treeitems_array[i].m_text or "";
      io.write("\t" .. bytes_str .. "\t|\t" .. treeitem_str .. "\n");
    end

    io.write("]]------------------------------------------------------------------------------------------------------------------------------\n\n\n");
  end

  return plugin_tester;
end
--[-----------------------------------------------------------------------------------------------------------------------------------------------------------------------]]



return wirebait


