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

local ByteArrayClass = require("wirebaitlib.primitives.ByteArray");
local PacketClass    = require("wirebaitlib.packet_data.Packet");
local TvbClass       = require("wirebaitlib.packet_data.Tvb");

--[[
    This class takes care of reading a pcap file, and delivers the data in the form of ethernet packets. When the end of
    the file is reached, this class returns nil, and no more packets will be delivered.
    To instantiate a PcapReader instance, one needs to provide a path to a pcap file.

    //Constructor
    <PcapReaderClass> PcapReaderClass.new(<string> pcap_filepath)
]]
local PcapReaderClass = {};

function PcapReaderClass.new(filepath)
    assert(filepath and type(filepath) == "string" and #filepath > 0, "A valid filepath must be provided!");
    local pcap_reader = {
        m_file = io.open(filepath, "rb"), --b is for binary, and is only there for windows
        m_timestamp_correction_sec = 0;
    }

    ----------------------------------------------- private methods ----------------------------------------------------

    --[[Reads byte_count bytes from file into a string in hexadecimal format ]]
    local function readFileAsHex(file, byte_count)
        local data = file:read(byte_count); --reads the binary data into a string. When printed this is gibberish
        data = data or "";
        local hex_data = string.gsub(data, ".", function (b) return string.format("%02X",string.byte(b)) end ); --turns the binary data into a string in hex format
        return hex_data;
    end

    local function closeReader(reader)
        if reader.m_file then
            reader.m_file:close();
            reader.m_file = nil;
        end
    end

    ----------------------------------------------- initialization -----------------------------------------------------

    assert(pcap_reader.m_file, "File at '" .. filepath .. "' not found!");
    local global_header_buf = TvbClass.new(ByteArrayClass.new(readFileAsHex(pcap_reader.m_file, 24)));
    assert(global_header_buf:len() == 24, "Pcap file is not large enough to contain a full global header.");
    assert(global_header_buf(0,4):bytes():toHex() == "D4C3B2A1", "Pcap file with magic number '" .. global_header_buf(0,4):bytes():toHex() .. "' is not supported! (Note that pcapng file are not supported either)");
    pcap_reader.m_timestamp_correction_sec = global_header_buf(8,4):le_uint();

    ----------------------------------------------- public methods -----------------------------------------------------

    --[[Reading next ethernet frame from the pcap file. If this function returns nil, there is no more data to read
    and the file it reads is closed.]]
    function pcap_reader:getNextEthernetFrame()
        assert(self.m_file, "PcapReader has been closed!");
        --Reading pcap packet_info header (this is not part of the actual ethernet frame)
        local pcap_hdr_buffer = TvbClass.new(ByteArrayClass.new(readFileAsHex(self.m_file, 16)));
        if pcap_hdr_buffer:len() < 16 then
            closeReader(self);
            assert(pcap_hdr_buffer:len() == 0, "Pcap ended in the middle of a packet!");
            return nil;
        end
        local frame_timestamp={};
        frame_timestamp.sec   = pcap_hdr_buffer(0,4):le_uint() + self.m_timestamp_correction_sec;
        frame_timestamp.u_sec = pcap_hdr_buffer(4,4):le_uint();
        local packet_length   = pcap_hdr_buffer(8,4):le_uint();
        local packet_buffer   = TvbClass.new(ByteArrayClass.new(readFileAsHex(self.m_file, packet_length)));
        if packet_buffer:len() < packet_length then
            closeReader(self);
            error("Pcap ended in the middle of a packet!");
        end
        assert(packet_buffer:len() > 14, "Unexpected packet_info in pcap! This frame cannot be an ethernet frame! (frame: " .. tostring(packet_buffer) .. ")");
        local ethernet_frame = PacketClass.new(packet_buffer, frame_timestamp);
        return ethernet_frame;
    end

    --[[Releases resources, in this case closing the opened file]]
    function pcap_reader:close()
        closeReader(self);
    end

    return pcap_reader;
end

return PcapReaderClass;