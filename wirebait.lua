--[[
    WireBait for Wireshark is a lua package to help write Wireshark 
    Dissectors in lua
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
  ProtoField = {}, 
  treeitem = {}, 
  buffer = {}, 
  packet = {}, 
  pcap_reader = {}, 
  ws_api = {},
  plugin_tester = {},
  
  state = { --[[ state to keep track of the dissector wirebait is testing ]]
      dissector_filepath = nil,
      proto = nil
    }
  }

--[[Local helper methods, only used withing this library]]
--[[Reads byte_count bytes from file into a string in hexadecimal format ]]
local function readFileAsHex(file, byte_count)
  local data = file:read(byte_count) --reads the binary data into a string. When printed this is gibberish
  data = data or "";
  local hex_data = string.gsub(data, ".", function (b) return string.format("%02X",string.byte(b)) end ) --turns the binary data into a string in hex format
  return hex_data
end

--[[prints an ip in octet format givent its little endian int32 representation]]
local function printIP(le_int_ip)
  local ip_str = ((le_int_ip & 0xFF000000) >> 24) .. "." .. ((le_int_ip & 0x00FF0000) >> 16) .. "." .. ((le_int_ip & 0x0000FF00) >> 8) .. "." .. (le_int_ip & 0x000000FF);
  return ip_str;
end

--[[converts a string in hex format into a big endian uint64 ]]
local function hexStringToUint64(hex_str)
  assert(#hex_str > 0, "hexStringToUint64() requires strict positive number of bytes!");
  assert(#hex_str <= 16, "hexStringToUint64() cannot convert more thant 8 bytes to a uint value!");
  if #hex_str <= 8 then
    return tonumber(hex_str,16);
  else
    local hex_str = string.format("%016s",hex_str) --left pad with zeros
    local byte_size=#hex_str/2
    local value = 0;
    for i=1,byte_size do
      value = value + tonumber(hex_str:sub(-2*i,-2*i+1),16)*16^(2*(i-1))
    end
    return value;
  end
end

--[[converts a string in hex format into a little endian uint64 ]]
local function le_hexStringToUint64(hex_str) --little endian version
  assert(#hex_str > 0, "Requires strict positive number of bytes!");
  assert(#hex_str <= 16, "Cannot convert more thant 8 bytes to an int value!");
  local hex_str = string.format("%-16s",hex_str):gsub(" ","0") --right pad with zeros

  --reading byte in inverted byte order
  local byte_size=#hex_str/2
  local value = 0;
  for i=1,byte_size do
    value = value + tonumber(hex_str:sub(2*i-1,2*i),16)*16^(2*(i-1))
  end
  return value;
end

local PROTOCOCOL_TYPES = {
  IPV4 = 0x800,
  UDP  = 0x11,
  TCP  =  0x06
};

--[[ Equivalent of [wireshark Proto](https://wiki.wireshark.org/LuaAPI/Proto#Proto) ]]
function wirebait.Proto.new(abbr, description)
  assert(description and abbr, "Proto argument should not be nil!")
  local proto = {
    _struct_type = "Proto";
    m_description = description,
    m_abbr = abbr,
    fields = {}, --protofields
    dissector = {}, --dissection function
  }

  assert(wirebait.state.proto == nil, "Multiple Protos are declared in the dissector file you are testing!");
  wirebait.state.proto = proto;
  return proto;
end

--[[ Equivalent of [wireshark ProtoField](https://wiki.wireshark.org/LuaAPI/Proto#ProtoField) ]]
function wirebait.ProtoField.new(abbr, name, _type, size)
  assert(name and abbr and _type, "Protofiled argument should not be nil!")
  local size_by_type = {uint8=1, uint16=2, uint32=4, uint64=8};
  local protofield = {
    _struct_type = "ProtoField";
    m_name = name;
    m_abbr = abbr;
    m_type = _type;
    m_size = size_by_type[_type] or size -- or error("Type " .. tostring(_type) .. " is of unknown size and no size is provided!");
  }
  
  function protofield:getValueFromBuffer(buffer)
    local extractValueFuncByType = {
      uint8 = function (buf) return buf(0,1):uint() end,
      uint16 = function (buf) return buf(0,2):uint() end,
      uint32 = function (buf) return buf(0,3):uint() end,
      uint64 = function (buf) return buf(0,4):uint64() end,
      string = function (buf) return 
        buf(0,buf:len()):string() 
        end,
    };
    
    local func = extractValueFuncByType[self.m_type];
    assert(func, "Unknown protofield type '" .. self.m_type .. "'!")
    return func(buffer);
  end

  return protofield;
end

function wirebait.ProtoField.string(name, abbr, ...) return wirebait.ProtoField.new(name, abbr, "string") end
function wirebait.ProtoField.uint8(name, abbr) return wirebait.ProtoField.new(name, abbr, "uint8") end
function wirebait.ProtoField.uint16(name, abbr) return wirebait.ProtoField.new(name, abbr, "uint16") end
function wirebait.ProtoField.uint32(name, abbr) return wirebait.ProtoField.new(name, abbr, "uint32") end
function wirebait.ProtoField.uint64(name, abbr) return wirebait.ProtoField.new(name, abbr, "uint64") end

--[[ Equivalent of [wireshark treeitem](https://wiki.wireshark.org/LuaAPI/TreeItem) ]]
function wirebait.treeitem.new(protofield, buffer, parent) 
  local treeitem = {
    m_protofield = protofield,
    m_parent = parent,
    m_child = nil,
    m_depth = 0,
    m_buffer = buffer;
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
      if texts then
        value = texts[1] --might be nil
        texts[1] = nil --removing value from the texts array
      end
    end
    assert(buffer or value, "Bug in this function, buffer and value cannot be both nil!");
    
    if texts then --texts override the value displayed in the tree including the header defined in the protofield
      print(prefix(tree.m_depth) .. table.concat(texts, " "));
    else
      io.write(prefix(tree.m_depth) .. proto.m_description .. "\n");
    end
    tree.m_child = wirebait.treeitem.new(proto, buffer, tree);
  end
  
  --[[ Private function adding a protofield to the provided treeitem ]]
  local function addProtoField(tree, protofield, buffer_or_value, texts)
    assert(buffer_or_value, "When adding a protofield, either a tvb range, or a value must be provided!");
    if type(buffer_or_value) == "string" or type(buffer_or_value) == "number" then
      --[[if no buffer provided, value will be appended to the treeitem, and no bytes will be highlighted]]
      value = buffer_or_value;
    else
      --[[if buffer is provided, value maybe provided, in which case it will override the value parsed from the buffer]]
      buffer = buffer_or_value
      assert(buffer._struct_type == "buffer", "Buffer expected but got another userdata type!")
      if texts then
        value = texts[1] --might be nil
        texts[1] = nil --removing value from the texts array
      end
    end
    assert(buffer or value, "Bug in this function, buffer and value cannot be both nil!");
    
    if texts then --texts override the value displayed in the tree including the header defined in the protofield
      print(prefix(tree.m_depth) .. table.concat(texts, " "));
    else
      local printed_value = tostring(value or protofield:getValueFromBuffer(buffer)) -- buffer(0, size):hex_string()
      io.write(prefix(tree.m_depth) .. protofield.m_name .. ": " .. printed_value .. "\n"); --TODO review the or buffer:len
    end
    tree.m_child = wirebait.treeitem.new(protofield, buffer, tree);
  end
  
  --[[ Private function adding a treeitem to the provided treeitem, without an associated protofield ]]
  local function addTreeItem(tree, proto, buffer_or_value, texts)
    error("TvbRange no supported yet!");
  end

  function treeitem:add(proto_or_protofield_or_buffer, buffer, value, ...)
    local texts = {...};
    if proto_or_protofield_or_buffer._struct_type == "Proto" then
      addProto(self, proto_or_protofield_or_buffer, buffer, value, texts);
    elseif proto_or_protofield_or_buffer._struct_type == "ProtoField" then
      addProtoField(self, proto_or_protofield_or_buffer, buffer, value, texts);
    elseif proto_or_protofield_or_buffer._struct_type == "Buffer" then --adding a tree item without protofield
      addTreeItem(self, proto_or_protofield_or_buffer, buffer, value, texts);
    else
      error("First argument in treeitem:add() should be a Proto or Profofield or a TvbRange");
    end
    return self.m_child;
  end

  return treeitem;
end

--[[ Equivalent of [wireshark ByteArray](https://wiki.wireshark.org/LuaAPI/ByteArray), [wireshark Tvb](https://wiki.wireshark.org/LuaAPI/Tvb#Tvb), and [wireshark TvbRange](https://wiki.wireshark.org/LuaAPI/Tvb#TvbRange) ]]
function wirebait.buffer.new(data_as_hex_string)
  assert(type(data_as_hex_string) == 'string', "Buffer should be based on an hexadecimal string!")
  assert(string.len(data_as_hex_string:gsub('%X','')) > 0 or data_as_hex_string:len() == 0, "String should be hexadecimal!")
  assert(string.len(data_as_hex_string) % 2 == 0, "String has its last byte cut in half!")

  local buffer = {
    _struct_type = "buffer",
    m_data_as_hex_str = data_as_hex_string,
  }
  local escape_replacements = {["\0"]="\\0", ["\t"]="\\t", ["\n"]="\\n", ["\r"]="\\r", }

  function buffer:len()
    return math.floor(string.len(self.m_data_as_hex_str)/2);
  end

  function buffer:le_uint()
    local size = math.min(#self.m_data_as_hex_str,8)
    return le_hexStringToUint64(string.sub(self.m_data_as_hex_str,0,size));
  end

  function buffer:le_uint64()
    local size = math.min(#self.m_data_as_hex_str,16)
    return le_hexStringToUint64(string.sub(self.m_data_as_hex_str,0,size));
  end;

  function buffer:uint()
    local size = math.min(#self.m_data_as_hex_str,8)
    return hexStringToUint64(string.sub(self.m_data_as_hex_str,0,size));
  end

  function buffer:uint64()
    local size = math.min(#self.m_data_as_hex_str,16)
    return hexStringToUint64(string.sub(self.m_data_as_hex_str,0,size));
  end;
  
  function buffer:int()
    local size = self:len();
    assert(size == 1 or size == 2 or size == 4, "Buffer must be 1, 2, or 4 bytes long for buffer:int() to work. (Buffer size: " .. self:len() ..")");
    local uint = self:uint();
    local sign_mask=tonumber("80" .. string.rep("00", size-1), 16);
    local val_mask=tonumber("EF" .. string.rep("FF", size-1), 16);
    if uint & sign_mask > 0 then --we're dealing with a negative number
      return -((~uint & val_mask) + 1);
    else --we are dealing with a positive number
      return uint;
    end
  end
  
  --[[this doesn't always in Lua 5.3 because self:uint64() returns a float if the number is too big. And you cannot perform bitwise operations
  on a float...huh... This looks like a lua bug to me, proof is that math.floor(2^64-1) returns a float and not an interger
  this means that for now, this logic works only with number less than 00FFFFFF FFFFFFFF]]
  function buffer:int64()
    local size = self:len();
    assert(size == 1 or size == 2 or size == 4 or size == 8, "Buffer must be 1, 2, 4, or 8 bytes long for buffer:int() to work. (Buffer size: " .. self:len() ..")");
    local uint = self:uint64();
    local sign_mask=tonumber("80" .. string.rep("00", size-1), 16);
    local val_mask=tonumber("EF" .. string.rep("FF", size-1), 16);
    if uint & sign_mask > 0 then --we're dealing with a negative number
      return -((~uint & val_mask) + 1);
    else --we are dealing with a positive number
      return uint;
    end
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

  function buffer:hex_string()
    return self.m_data_as_hex_str;
  end

  --c.f. [wireshark tvbrange](https://wiki.wireshark.org/LuaAPI/Tvb) for missing implementations such as float() le_float() etc..

  function buffer:__call(start, length) --allows buffer to be called as a function 
    assert(start >= 0, "Start position is positive!");
    assert(length > 0, "Length is strictly positive!");
    assert(start + length <= self:len(), "Index get out of bounds!")
    return wirebait.buffer.new(string.sub(self.m_data_as_hex_str,2*start+1, 2*(start+length)))            
  end

  function buffer:__tostring()
    return "[buffer: 0x" .. self.m_data_as_hex_str .. "]";
  end
  setmetatable(buffer, buffer)

  return buffer;
end

--[[ Data structure holding an ethernet packet, which is used by wirebait to hold packets read from pcap files 
     At initialization, all the member of the struct are set to nil, which leaves the structure actually empty. The point here
     is that you can visualize what the struct would look like once populated]]
function wirebait.packet.new (packet_buffer, packet_no)
  local packet = {
    packet_number = packet_no,
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
  if packet.ethernet.type ~= PROTOCOCOL_TYPES.IPV4 then
    packet.ethernet.other = packet_buffer(14,packet_buffer:len() - 14);
  else
    --[[IPV4 layer parsing]]
    packet.ethernet.ipv4.protocol = packet_buffer(23,1):uint();
    packet.ethernet.ipv4.src_ip = packet_buffer(26,4):uint();
    packet.ethernet.ipv4.dst_ip = packet_buffer(30,4):uint();

    --[[UDP layer parsing]]
    if packet.ethernet.ipv4.protocol == PROTOCOCOL_TYPES.UDP then
      packet.ethernet.ipv4.udp.src_port = packet_buffer(34,2):uint();
      packet.ethernet.ipv4.udp.dst_port = packet_buffer(36,2):uint();
      packet.ethernet.ipv4.udp.data = packet_buffer(42,packet_buffer:len() - 42);
    elseif packet.ethernet.ipv4.protocol == PROTOCOCOL_TYPES.TCP then
      --[[TCP layer parsing]]
      packet.ethernet.ipv4.tcp.src_port = packet_buffer(34,2):uint();
      packet.ethernet.ipv4.tcp.dst_port = packet_buffer(36,2):uint();
      -- for Lua 5.3 and above
      local tcp_hdr_len = 4 * ((packet_buffer(46,1):uint() & 0xF0) >> 4);
      -- for Lua 5.2 and below
      --local tcp_hdr_len = bit32.arshift(bit32.band(packet_buffer(46,1):uint(), 0xF0)) * 4;
      local tcp_payload_start_index = 34 + tcp_hdr_len;
      if packet_buffer:len() > tcp_payload_start_index then
        packet.ethernet.ipv4.tcp.data = packet_buffer(tcp_payload_start_index, packet_buffer:len() - tcp_payload_start_index);
      end
    else
      --[[Unknown transport layer]]
      packet.ethernet.ipv4.other = packet_buffer(14,packet_buffer:len() - 14);
    end
  end

  function packet:info()
    if self.ethernet.type == PROTOCOCOL_TYPES.IPV4 then
      if self.ethernet.ipv4.protocol == PROTOCOCOL_TYPES.UDP then
        return "Frame #" .. self.packet_number .. ". UDP packet from " .. printIP(self.ethernet.ipv4.src_ip) .. ":" ..  self.ethernet.ipv4.udp.src_port 
        .. " to " .. printIP(self.ethernet.ipv4.dst_ip) .. ":" ..  self.ethernet.ipv4.udp.dst_port .. ". Payload: " .. tostring(self.ethernet.ipv4.udp.data);
      elseif self.ethernet.ipv4.protocol == PROTOCOCOL_TYPES.TCP then
        return "Frame #" .. self.packet_number .. ". TCP packet from " .. printIP(self.ethernet.ipv4.src_ip) .. ":" ..  self.ethernet.ipv4.tcp.src_port 
        .. " to " .. printIP(self.ethernet.ipv4.dst_ip) .. ":" ..  self.ethernet.ipv4.tcp.dst_port .. ". Payload: " .. tostring(self.ethernet.ipv4.tcp.data);
      else
        --[[Unknown transport layer]]
        return "Frame #" .. self.packet_number .. ". IPv4 packet from " .. self.ethernet.ipv4.src_ip .. " to " .. self.ethernet.ipv4.dst_ip;
      end
    else
      return "Frame #" .. self.packet_number .. ". Ethernet packet (non ipv4)";
    end
  end

  return packet;
end

function wirebait.pcap_reader.new(filepath)
  local pcap_reader = {
    m_file = io.open(filepath, "rb"), --b is for binary, and is only there for windows
    m_packet_number = 1
  }

  --[[Performing various checks before reading the packet data]]
  assert(pcap_reader.m_file, "File at '" .. filepath .. "' not found!");
  local global_header_buf = wirebait.buffer.new(readFileAsHex(pcap_reader.m_file, 24));
  assert(global_header_buf:len() == 24, "Pcap file is not large enough to contain a full global header.");
  assert(global_header_buf(0,4):hex_string() == "D4C3B2A1", "Pcap file with magic number '" .. global_header_buf(0,4):hex_string() .. "' is not supported!"); 

  --[[Reading pcap file and returning the next ethernet frame]]
  function pcap_reader:getNextEthernetFrame()
    --Reading pcap packet header (this is not part of the actual ethernet frame)
    local pcap_hdr_buffer = wirebait.buffer.new(readFileAsHex(self.m_file, 16));
    if pcap_hdr_buffer:len() < 16 then -- this does not handle live capture
      return nil;
    end
    --print("Pcap Header: " .. tostring(pcap_hdr_buffer));
    local packet_length = pcap_hdr_buffer(8,4):le_uint();

    local packet_buffer = wirebait.buffer.new(readFileAsHex(self.m_file, packet_length));
    if packet_buffer:len() < packet_length then -- this does not handle live capture
      return nil;
    end
    --print("     Packet: " .. tostring(packet_buffer));
    assert(packet_buffer:len() > 14, "Unexpected packet in pcap! This frame cannot be an ethernet frame! (frame: " .. tostring(packet_buffer) .. ")");
    local ethernet_frame = wirebait.packet.new(packet_buffer, self.m_packet_number);
    self.m_packet_number = self.m_packet_number + 1;
    return ethernet_frame;
  end

--	self_pcap_reader:getNextIPPayload = getNextIPPayload;
--	setmetatable(self_pcap_reader, self)
--	self.__index = self
  return pcap_reader;
end

function wirebait.plugin_tester.new(dissector_filepath, pcap_filepath)
  local plugin_tester = {
    m_pcap_reader = wirebait.pcap_reader.new(pcap_filepath),
    m_dissector_filepath = dissector_filepath
  };
  --wireshark.wirebait_handle = plugin_tester;

  function plugin_tester:run()
    repeat
      local packet = self.m_pcap_reader:getNextEthernetFrame()
      if packet then
        print(packet:info());
        Proto = wirebait.Proto;
        ProtoField = wirebait.ProtoField;
        dofile(self.m_dissector_filepath);
        local buffer = packet.ethernet.ipv4.udp.data or packet.ethernet.ipv4.tcp.data;
        local root_tree = wirebait.treeitem.new(buffer);
        if buffer then
          wirebait.state.proto.dissector(buffer, nil, root_tree);
        end
        break;
      end
    until packet == nil
  end

  return plugin_tester;
end

test = wirebait.plugin_tester.new("C:/Users/Marko/Documents/GitHub/wirebait/example/simple_dissector.lua", "C:/Users/Marko/Desktop/pcaptest.pcap");

test:run()
buf = wirebait.buffer.new("0FFFFFFFFFFFFFFF")
buf = wirebait.buffer.new("6FFFFFFFFFFFFFFF")
buf = wirebait.buffer.new("FFFFFFAB")
print((buf:int()))
--buf:int();
--test = function(a, b, c, ...)
--  print("a: " .. a)
--  print("b: " .. b)
--  print("c: " .. c)
  
--  args={...}
--  value = args[1]
  
--end

--test(1,2,3)

return wirebait


