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


local Utils = require("wirebaitlib.primitives.Utils");

--[[
    Packet class is meant to hold packet data, and allows wirebait to extract packet information when printing the
    output of a dissection.
    To instantiate a PacketClass instance, on needs to provide the underlying Tvb and the packet timestamp.

    //Constructor
    <PacketClass> PacketClass.new(<Tvb> packet_buffer, <Timestamp> pkt_timestamp)
]]
local PacketClass = {};

local PROTOCOL_TYPES = {
    IPV4 = 0x800,
    UDP  = 0x11,
    TCP  =  0x06
};

--[[
    Class holding a packet in the form of an ethernet frame, which is used by Wirebait to hold packets read from pcap
    files. At initialization, all the member of the struct are set to nil, which leaves the structure actually empty.
    The point here is that you can visualize what the struct would look like once populated.
]]
function PacketClass.new (packet_buffer, pkt_timestamp)
    local packet = {
        _struct_type = "Packet",
        timestamp = {
            sec = pkt_timestamp.sec,
            u_sec = pkt_timestamp.u_sec,
        },
        ethernet = {
            dst_mac = nil, --string in hex format e.g. "EC086B703682" (which would correspond to the mac address ec:08:6b:70:36:82
            src_mac = nil,
            type = nil, --type as unsigned int, e.g. 0x0800 for IPV4
            ipv4 = {
                protocol = nil, --dissector as unsigned int, e.g. 0x06 for TCP
                dst_ip   = nil, -- uint32 little endian
                src_ip   = nil, -- uint32 little endian
                udp = {
                    src_port = nil,
                    dst_port = nil,
                    data     = nil,
                },
                tcp = {
                    src_port = nil,
                    dst_port = nil,
                    data     = nil,
                },
                other_data = nil, -- exist if pkt is not tcp nor udp
            },
            other_data = nil -- exist if pkt is not ip
        },
        data_ref = nil --reference to the data (either ipv4.udp.data or ipv4.tcp.data etc..)
    }

    ----------------------------------------------- initialization -----------------------------------------------------

    assert(packet_buffer and Utils.typeof(packet_buffer) == "Tvb", "Packet cannot be constructed without a buffer!");
    --[[Ethernet layer parsing]]
    packet.ethernet.dst_mac = packet_buffer(0,6):bytes();
    packet.ethernet.src_mac = packet_buffer(6,6):bytes();
    packet.ethernet.type = packet_buffer(12,2):uint(); --e.g 0x0800 for IP
    if packet.ethernet.type ~= PROTOCOL_TYPES.IPV4 then
        packet.ethernet.other = packet_buffer(14,packet_buffer:len() - 14);
        packet.data_ref = packet.ethernet.other_data;
    else
        --[[IPV4 layer parsing]]
        packet.ethernet.ipv4.protocol = packet_buffer(23,1):uint();
        packet.ethernet.ipv4.src_ip   = packet_buffer(26,4):uint();
        packet.ethernet.ipv4.dst_ip   = packet_buffer(30,4):uint();

        --[[UDP layer parsing]]
        if packet.ethernet.ipv4.protocol == PROTOCOL_TYPES.UDP then
            packet.ethernet.ipv4.udp.src_port = packet_buffer(34,2):uint();
            packet.ethernet.ipv4.udp.dst_port = packet_buffer(36,2):uint();
            assert(packet_buffer:len() >= 42, "Packet buffer is of invalid size!")
            packet.ethernet.ipv4.udp.data = packet_buffer(42,packet_buffer:len() - 42):tvb();
            packet.data_ref = packet.ethernet.ipv4.udp.data;
        elseif packet.ethernet.ipv4.protocol == PROTOCOL_TYPES.TCP then
        --[[TCP layer parsing]]
            packet.ethernet.ipv4.tcp.src_port = packet_buffer(34,2):uint();
            packet.ethernet.ipv4.tcp.dst_port = packet_buffer(36,2):uint();
            local tcp_hdr_len = 4 * bit32.rshift(bit32.band(packet_buffer(46,1):uint(), 0xF0), 4);
            local tcp_payload_start_index = 34 + tcp_hdr_len;
            assert(packet_buffer:len() >= tcp_payload_start_index, "Packet buffer is of invalid size!")
            packet.ethernet.ipv4.tcp.data = packet_buffer(tcp_payload_start_index, packet_buffer:len() - tcp_payload_start_index):tvb();
            packet.data_ref = packet.ethernet.ipv4.tcp.data;
        else
        --[[Unknown transport layer]]
            packet.ethernet.ipv4.other = packet_buffer(14,packet_buffer:len() - 14);
            packet.data_ref = packet.ethernet.ipv4.other_data;
        end
        --Offset reset to 0 because the dissector should not see any offset
        packet.data_ref.m_offset = 0;
    end

    ----------------------------------------------- public methods -----------------------------------------------------

    function packet:getData()
        return self.data_ref;
    end

    function packet:getIPProtocol()
        return self.ethernet.ipv4.protocol;
    end

    function packet:getSrcIP()
        return Utils.int32IPToString(self.ethernet.ipv4.src_ip);
    end

    function packet:getDstIP()
        return Utils.int32IPToString(self.ethernet.ipv4.dst_ip);
    end

    function packet:getSrcPort()
        local ip_proto = self:getIPProtocol();
        if ip_proto == PROTOCOL_TYPES.UDP then
            return self.ethernet.ipv4.udp.src_port
        elseif ip_proto == PROTOCOL_TYPES.TCP then
            return self.ethernet.ipv4.tcp.src_port
        else
            error("Packet:getSrcPort() only supports getSrcPort() for IP/UDP and IP/TCP protocols!")
        end
    end

    function packet:getDstPort()
        local ip_proto = self:getIPProtocol();
        if ip_proto == PROTOCOL_TYPES.UDP then
            return self.ethernet.ipv4.udp.dst_port
        elseif ip_proto == PROTOCOL_TYPES.TCP then
            return self.ethernet.ipv4.tcp.dst_port
        else
            error("Packet:getDstPort() only supports getDstPort() for IP/UDP and IP/TCP protocols!")
        end
    end

    function packet:protocol()
        local ip_proto = self:getIPProtocol();
        if ip_proto == PROTOCOL_TYPES.UDP then
            return "UDP";
        elseif ip_proto == PROTOCOL_TYPES.TCP then
            return "TCP";
        else
            error("Packet:protocol() only supports IP/UDP and IP/TCP protocols!")
        end
    end

    function packet:len()
        return self.data_ref:len();
    end

    function packet:printInfo(frame_number, cols)
        assert(self.ethernet.type == PROTOCOL_TYPES.IPV4, "Only IPv4 packets are supported!");
        local function ellipsis(value, char_count)
            local val_str = tostring(value);
            return #val_str and (val_str:sub(0,char_count-3) .. "..") or val_str;
        end
        local src    = self:getSrcIP();
        local dst    = self:getDstIP();
        local length = self:len();
        --[[Creating a UTC timestamp string.
        For instance: if the date is sept 1st 2017 2:02 am  the timestamp will be "2017-09-01 02:02:47.23864" ]]
        --local timestamp_str = os.date("!%Y-%m-%d", self.timestamp.sec) .. " " .. os.date("!%H:%M:%S.".. self.timestamp.u_sec , self.timestamp.sec)
        local timestamp_str = os.date("!%H:%M:%S.".. self.timestamp.u_sec , self.timestamp.sec) --only displaying the time
        io.write(string.format("%-12s| %-20s| %-18s| %-18s| %-10s| %-10s| %-50s\n",
                "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"));
        io.write(string.format("%-12s| %-20s| %-18s| %-18s| %-10s| %-10d| %-50s\n",
                frame_number, ellipsis(timestamp_str, 20), src, dst, ellipsis(cols.protocol,10), length, ellipsis(cols.info, 50)));
    end

    return packet;
end

return PacketClass;