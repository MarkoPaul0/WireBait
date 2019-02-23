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

local ByteArray = require("wirebaitlib.primitives.ByteArray");
local Packet = require("wirebaitlib.packet_data.Packet");
local Tvb = require("wirebaitlib.packet_data.Tvb");

--[[Reads byte_count bytes from file into a string in hexadecimal format ]]
local function readFileAsHex(file, byte_count)
    local data = file:read(byte_count); --reads the binary data into a string. When printed this is gibberish
    data = data or "";
    local hex_data = string.gsub(data, ".", function (b) return string.format("%02X",string.byte(b)) end ); --turns the binary data into a string in hex format
    return hex_data;
end

local PcapReader = {}

function PcapReader.new(filepath)
    assert(filepath and type(filepath) == "string" and #filepath > 0, "A valid filepath must be provided!");
    local pcap_reader = {
        m_file = io.open(filepath, "rb"), --b is for binary, and is only there for windows
        m_timestamp_correction_sec = 0;
    }

    --[[Performing various checks before reading the packet_info data]]
    assert(pcap_reader.m_file, "File at '" .. filepath .. "' not found!");
    local global_header_buf = Tvb.new(ByteArray.new(readFileAsHex(pcap_reader.m_file, 24)));
    assert(global_header_buf:len() == 24, "Pcap file is not large enough to contain a full global header.");
    assert(global_header_buf(0,4):bytes():toHex() == "D4C3B2A1", "Pcap file with magic number '" .. global_header_buf(0,4):bytes():toHex() .. "' is not supported! (Note that pcapng file are not supported either)");
    pcap_reader.m_timestamp_correction_sec = global_header_buf(8,4):le_uint();

    --[[Reading pcap file and returning the next ethernet frame]]
    function pcap_reader:getNextEthernetFrame()
        --Reading pcap packet_info header (this is not part of the actual ethernet frame)
        local pcap_hdr_buffer = Tvb.new(ByteArray.new(readFileAsHex(self.m_file, 16)));
        if pcap_hdr_buffer:len() < 16 then -- this does not handle live capture
            return nil;
        end
        local frame_timestamp={};
        frame_timestamp.sec = pcap_hdr_buffer(0,4):le_uint() + self.m_timestamp_correction_sec;
        frame_timestamp.u_sec = pcap_hdr_buffer(4,4):le_uint();
        local packet_length = pcap_hdr_buffer(8,4):le_uint();
        local packet_buffer = Tvb.new(ByteArray.new(readFileAsHex(self.m_file, packet_length)));
        if packet_buffer:len() < packet_length then -- this does not handle live capture
            return nil;
        end
        assert(packet_buffer:len() > 14, "Unexpected packet_info in pcap! This frame cannot be an ethernet frame! (frame: " .. tostring(packet_buffer) .. ")");
        local ethernet_frame = Packet.new(packet_buffer, frame_timestamp);
        return ethernet_frame;
    end

    return pcap_reader;
end

return PcapReader;