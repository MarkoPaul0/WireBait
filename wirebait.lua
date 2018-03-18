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
      treeitems_array = {}
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

--[[Converts a string in hex format into a big endian uint64 ]]
--[[In lua there is no real integer type, and past 2^53 numbers are interpreted as double, which is why uin64t are handled in 2 words]]
local function hexStringToUint64(hex_str)
  assert(#hex_str > 0, "hexStringToUint64() requires strict positive number of bytes!");
  assert(#hex_str <= 16, "hexStringToUint64() cannot convert more thant 8 bytes to a uint value!");
  if #hex_str <= 8 then
    return tonumber(hex_str,16);
  else
    local hex_str = string.format("%016s",hex_str) --left pad with zeros
    hex_str = hex_str:gsub(" ","0"); --for some reaon in lua 5.3 "%016s" letf pads with zeros. These version issues are annoying to say the least...
    local first_word_val = tonumber(string.sub(hex_str, 1,8),16);
    local second_word_val = tonumber(string.sub(hex_str, 9,16),16);
    local value = math.floor((first_word_val << 32) + second_word_val)
    return value;
  end
end

local PROTOCOL_TYPES = {
  IPV4 = 0x800,
  UDP  = 0x11,
  TCP  =  0x06
};
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
      uint64  = function (buf) return buf:uint64() & (mask or 0xFFFFFFFFFFFFFFFF) end,
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
        str_value = value_string .. " (0x" .. buffer:hex_string() .. ")";
      else
        str_value = "0x" .. buffer:hex_string();
      end
    elseif self.m_base == wirebait.base.HEX_DEC then 
      if value_string then 
        str_value =  value_string .. " (0x" .. buffer:hex_string() .. ")";
      else
        str_value = "0x" .. buffer:hex_string() .. " (" .. str_value .. ")";
      end
    elseif self.m_base == wirebait.base.DEC_HEX then 
      if value_string then 
        str_value =  value_string .. " (" .. value .. ")";
      else
        str_value =  str_value .. " (0x" .. buffer:hex_string() .. ")";
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
      local printed_value = tostring(value or protofield:getDisplayValueFromBuffer(buffer)) -- buffer(0, size):hex_string()
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
    return hexStringToUint64(self:bytes());
  end

  function buffer:uint64()
    assert(self:len() <= 8, "tvbrange:uint64() cannot decode more than 8 bytes! (len = " .. self:len() .. ")");
    return hexStringToUint64(self:bytes());
  end;

  function buffer:le_uint()
    assert(self:len() <= 4, "tvbrange:le_uint() cannot decode more than 4 bytes! (len = " .. self:len() .. ")");
    return hexStringToUint64(self:swapped_bytes());
  end

  function buffer:le_uint64()
    assert(self:len() <= 8, "tvbrange:le_uint64() cannot decode more than 8 bytes! (len = " .. self:len() .. ")");
    return hexStringToUint64(self:swapped_bytes());
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
      eth_addr = eth_addr .. sep .. self(i-1,1):hex_string();
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
    local be_hex_str = swapBytes(self:hex_string());
    return wirebait.buffer.new(be_hex_str):ustring();
  end

  function buffer:le_ustringz()
    local be_hex_str = swapBytes(self:hex_string());
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

  function buffer:hex_string()
    return self.m_data_as_hex_str;
  end

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
  packet.ethernet.dst_mac = packet_buffer(0,6):hex_string();
  packet.ethernet.src_mac = packet_buffer(6,6):hex_string();
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
  assert(global_header_buf(0,4):hex_string() == "D4C3B2A1", "Pcap file with magic number '" .. global_header_buf(0,4):hex_string() .. "' is not supported! (Note that pcapng file are not supported either)"); 

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
      str = str .. " " .. buffer(i-1,1):hex_string();
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

--local dissector_tester = wirebait.plugin_tester.new({dissector_filepath="./example/smp_dissector_ex1.lua", only_show_dissected_packets=true});
----Example 1: dissecting data from a hexadecimal string
--dissector_tester:dissectHexData("0 \t\r\n  000 00 0 0 00 00 0 B24 11   aa  00 01 57 69 72 65 62 61 69 74 5c 30 00 " .. 
--  "00000 0 000000 0 0 0 00000 00 00 00 72 63 68 657  2  20 4    3 39 20 76 3 1 0 0");


return wirebait


