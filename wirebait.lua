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

local wirebait = { plugin_tester = {}, pcap_reader = {}, packet = {}, plugin = {}}
local wireshark = require("wireshark_api_mock");
local buffer = require("wireshark_api_mock").buffer; --using the buffer class from wireshark_mock to parse the binary data from the pcap file

--[[Local helper methods, only used withing this library]]
--[[Reads byte_count bytes from file into a string in hexadecimal format ]]
local function readFileAsHex(file, byte_count)
	data = file:read(byte_count) --reads the binary data into a string. When printed this is gibberish
	data = data or "";
	hex_data = string.gsub(data, ".", function (b) return string.format("%02X",string.byte(b)) end ) --turns the binary data into a string in hex format
	return hex_data
end

--[[prints an ip in octet format givent its little endian int32 representation]]
local function printIP(le_int_ip)
	local ip_str = ((le_int_ip & 0xFF000000) >> 24) .. "." .. ((le_int_ip & 0x00FF0000) >> 16) .. "." .. ((le_int_ip & 0x0000FF00) >> 8) .. "." .. (le_int_ip & 0x000000FF);
	return ip_str;
end

local PROTOCOCOL_TYPES = {
	IPV4 = 0x800,
	UDP  = 0x11,
	TCP  =  0x06
};

function wirebait.packet.new (packet_buffer, packet_no)
	local self = {
		packet_number = packet_no,
		ethernet = {
			dst_mac = "", --string in hex format e.g. "EC086B703682" (which would correspond to the mac address ec:08:6b:70:36:82
			src_mac = "",
			type = 0, --type as unsigned int, e.g. 0x0800 for IPV4
			ipv4 = {
				protocol = 0, --protocol as unsigned int, e.g. 0x06 for TCP
				dst_ip = 0, -- uint32 little endian
				src_ip = 0, -- uint32 little endian
				udp = {
					src_port = 0,
					dst_port = 0,
					data = {},
				},
				tcp = {
					src_port = 0,
					dst_port = 0,
					data = {},
				},
				other_data = {}, --if not tcp nor udp
			}, 
			other_data = {} --if not ip
		}
	}
	--assert(packet_buffer:len() > 14, "Invalid packet " .. packet_buffer .. ". It is too small!");
	--[[Ethernet layer parsing]]
	self.ethernet.dst_mac = packet_buffer(0,6):hex_string();
	self.ethernet.src_mac = packet_buffer(6,6):hex_string();
	self.ethernet.type = packet_buffer(12,2):uint(); --e.g 0x0800 for IP
	if self.ethernet.type ~= PROTOCOCOL_TYPES.IPV4 then
		self.ethernet.other = packet_buffer(14,packet_buffer:len() - 14);
	else
		--[[IPV4 layer parsing]]
		self.ethernet.ipv4.protocol = packet_buffer(23,1):uint();
		self.ethernet.ipv4.src_ip = packet_buffer(26,4):uint();
		self.ethernet.ipv4.dst_ip = packet_buffer(30,4):uint();

		--[[UDP layer parsing]]
		if self.ethernet.ipv4.protocol == PROTOCOCOL_TYPES.UDP then
			self.ethernet.ipv4.udp.src_port = packet_buffer(34,2):uint();
			self.ethernet.ipv4.udp.dst_port = packet_buffer(36,2):uint();
			self.ethernet.ipv4.udp.data = packet_buffer(42,packet_buffer:len() - 42);
		elseif self.ethernet.ipv4.protocol == PROTOCOCOL_TYPES.TCP then
			--[[TCP layer parsing]]
			self.ethernet.ipv4.tcp.src_port = packet_buffer(34,2):uint();
			self.ethernet.ipv4.tcp.dst_port = packet_buffer(36,2):uint();
			-- for Lua 5.3 and above
			local tcp_hdr_len = 4 * ((packet_buffer(46,1):uint() & 0xF0) >> 4);
			-- for Lua 5.2 and below
			--local tcp_hdr_len = bit32.arshift(bit32.band(packet_buffer(46,1):uint(), 0xF0)) * 4;
			local tcp_payload_start_index = 34 + tcp_hdr_len;
			if packet_buffer:len() > tcp_payload_start_index then
				self.ethernet.ipv4.tcp.data = packet_buffer(tcp_payload_start_index, packet_buffer:len() - tcp_payload_start_index);
			end
		else
			--[[Unknown transport layer]]
			self.ethernet.ipv4.other = packet_buffer(14,packet_buffer:len() - 14);
		end
	end
	
	info = function()
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
	
	self.info = info;
	return self;
end


function wirebait.pcap_reader:new (filepath)
	local self = {
		m_file = io.open(filepath, "rb"), --b is for binary, and is only there for windows
		m_packet_number = 1
	}
	
	--[[Performing various checks before reading the packet data]]
	assert(self.m_file, "File at '" .. filepath .. "' not found!");
	local global_header_buf = buffer.new(readFileAsHex(self.m_file, 24));
	assert(global_header_buf:len() == 24, "Pcap file is not large enough to contain a full global header.");
	assert(global_header_buf(0,4):hex_string() == "D4C3B2A1", "Pcap file with magic number '" .. global_header_buf(0,4):hex_string() .. "' is not supported!"); 
	
	--[[Reading pcap file and returning the next ethernet frame]]
	local getNextEthernetFrame = function()
		--Reading pcap packet header (this is not part of the actual ethernet frame)
		pcap_hdr_buffer = buffer.new(readFileAsHex(self.m_file, 16));
		if pcap_hdr_buffer:len() < 16 then -- this does not handle live capture
			return nil;
		end
		--print("Pcap Header: " .. tostring(pcap_hdr_buffer));
		packet_length = pcap_hdr_buffer(8,4):le_uint();
		
		packet_buffer = buffer.new(readFileAsHex(self.m_file, packet_length));
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
	return {
		getNextEthernetFrame = getNextEthernetFrame
	};
end


function wirebait.ws_api.new(wireshark_plugin)
	local api = {
		
	};
	
	function api:registerField()
	end
	
	function api:add(protofield)
	end
end


function wirebait.plugin_tester:new(plugin_filepath, pcap_filepath)
	local plugin_tester = {
		some_int = 0;
	};
	wireshark.wirebait_handle = plugin_tester;

	function plugin_tester:run()
		reader = wirebait.pcap_reader:new(pcap_filepath);
		repeat
			packet = reader:getNextEthernetFrame()
			if packet then
				print(packet:info());
			end
		until packet == nil
	end

	return plugin_tester;
end

test = wirebait.plugin_tester:new("bs", "more bs");
wireshark.Proto.new("smp", "simple proto");
test:add(10);
wireshark.Proto.new("smp", "simple proto");
test:add(2);
wireshark.Proto.new("smp", "simple proto");

wirebait.test_plugin(nil, "C:/Users/Marko/Desktop/pcaptest.pcap");



