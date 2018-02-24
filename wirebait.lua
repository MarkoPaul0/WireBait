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

local wirebait = { plugin_tester = {}, pcap_reader = {}}
local buffer = require("wireshark_api_mock").buffer; --using the buffer class from wireshark_mock to parse the binary data from the pcap file

--[[Reads byte_count bytes from file into a string in hexadecimal format ]]
local function readFileAsHex(file, byte_count)
	data = file:read(byte_count) --reads the binary data into a string. When printed this is gibberish
	hex_data = string.gsub(data, ".", function (b) return string.format("%02X",string.byte(b)) end ) --turns the binary data into a string in hex format
	return hex_data
end


function wirebait.pcap_reader:new (filepath)
	local self = {
		m_file = io.open(filepath, "rb"), --b is for binary, and is only there for windows
	}
	
	assert(self.m_file, "File at '" .. filepath .. "' not found!");
	
	--[[Reads data from file into a string in hexadecimal format ]]
--	function readHexData(byte_count)
--		data = self.m_file:read(byte_count) --reads the binary data into a string. When printed this is gibberish
--		hex_data = string.gsub(data, ".", function (b) return string.format("%02X",string.byte(b)) end ) --turns the binary data into a string in hex format
--		return hex_data
--	end
	
	--[[Performing various checks before reading the packet data]]
	local global_header_buf = buffer.new(readFileAsHex(self.m_file, 24));
	assert(global_header_buf:len() == 24, "Pcap file is not large enough to contain a full global header."); 
	assert(global_header_buf(0,4):hex_string() == "D4C3B2A1", "Pcap file with magic number '" .. global_header_buf(0,4):hex_string() .. "' is not supported!"); 
	
	local getNextIPPayload = function()
		--Reading pcap packet header (this is not part of the actual ethernet frame)
		pcap_hdr_buffer = buffer.new(readFileAsHex(self.m_file, 16));
		print("Header: " .. tostring(pcap_hdr_buffer));
		packet_length = pcap_hdr_buffer(8,4):le_uint();
		
		--Reading actual packet data
		packet_data = readFileAsHex(self.m_file, packet_length);
		print("Packet: " .. tostring(packet_data));
	end
	
--	self_pcap_reader:getNextIPPayload = getNextIPPayload;
--	setmetatable(self_pcap_reader, self)
--	self.__index = self
	return {
		getNextIPPayload = getNextIPPayload
	};
end

reader = wirebait.pcap_reader:new("C:/Users/Marko/Desktop/pcaptest.pcap");


reader:getNextIPPayload()
print("\n")
reader:getNextIPPayload()
print("\n")
reader:getNextIPPayload()
print("\n")
reader:getNextIPPayload()
print("\n")
reader:getNextIPPayload()
print("\n")
reader:getNextIPPayload()
