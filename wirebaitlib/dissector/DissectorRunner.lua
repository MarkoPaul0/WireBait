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

local DissectorTableClass = require("wirebaitlib.dissector.DissectorTable");
local TreeItemClass       = require("wirebaitlib.dissector.TreeItem");
local TvbClass            = require("wirebaitlib.packet_data.Tvb");
local ByteArrayClass      = require("wirebaitlib.primitives.ByteArray");
local PcapReaderClass     = require("wirebaitlib.packet_data.PcapReader");
local PacketInfoClass     = require("wirebaitlib.packet_info.PacketInfo");
local Utils               = require("wirebaitlib.primitives.Utils");

--[[
    The DissectorRunnerClass is the main component users interact with when using Wirebait. It loads all of the
    necessary Wirebait components in order to run a dissector on user-specified data.
    A DissectorRunnerClass instance can run a dissector on either a pcap file or a string representing packet data in
    hexadecimal format. To create a DissectorRunner, one needs to provide a table with various parameters, including the
    path to the tested dissector.

    // Constructor
    <DissectorRunnerClass> DissectorRunnerClass.new(<table> options_table)
    options_table should contain the following:
    - options_table.dissector_filepath should contain the path to the dissector which will be invoked to dissect packet
    data.
    - options_table.only_show_dissected_packets is a boolean that determines if the output of the dissection should
    contain packets that were dissected.

    // Public Methods
    // Uses the dissector loaded at construction time to dissect the data in the pcap file at the provided path
    <void> DissectorRunnerClass:dissectPcap(<string> pcap_filepath)

    // Uses the dissector loaded at construction time to dissect the packet data represented by a string in hexadecimal
    // format. Note that this data should only represent the payload meant to be dissected by a dissector, ommiting any
    // encapsulating layer data.
    <void> DissectorRunnerClass:dissectHexData(<string> hex_data)
]]
local DissectorRunnerClass = {};

--TODO: duplicate with Packet.lua
local PROTOCOL_TYPES = {
    IPV4 = 0x800,
    UDP  = 0x11,
    TCP  =  0x06
};

--[[
    This method creates an Object used by the DissectorRunner to keep track of its state. The state can be updated by
    different components of Wirebait.
]]
local function createRunnerState()
    local runner_state = {
        dissector_filepath = nil,
        proto              = nil,
        packet_info = {
            cols            = {},
            treeitems_array = {} --treeitems are added to that array so they can be displayed after the whole packet is dissected
        },
        dissector_table = DissectorTableClass.new()
    };

    --TODO: this is not used for now. Remove?
    function runner_state:reset()
        self.dissector_filepath = nil;
        self.proto = nil;
        self.packet_info.cols = {};
        self.packet_info.treeitems_array = {};
        self.dissector_table = DissectorTableClass.new();
    end

    return runner_state;
end

function DissectorRunnerClass.new(options_table) --[[options_table uses named arguments]] --TODO: document a comprehensive list of named arguments
    options_table = options_table or {};
    local dissector_runner = {
        m_dissector_filepath = options_table.dissector_filepath or arg[0], --if dissector_filepath is not provided, takes the path to the script that was launched
        m_only_show_dissected_packets = options_table.only_show_dissected_packets or false
    };

    --dissector_chunk_func is a function, which when invoked will load the dissector (but not run it)
    local dissector_chunk_func = loadfile(dissector_runner.m_dissector_filepath);
    if not dissector_chunk_func then
        error("File '" .. dissector_runner.m_dissector_filepath .. "' could not be found, or you don't have permissions!");
    end

    --Setting up the environment before invoking dofile() on the dissector script
    local newgt = {};
    setmetatable(newgt, {__index = _G}) -- have the new environment inherits from the current one to garanty access to standard functions
    newgt._WIREBAIT_ON_    = true;
    newgt.UInt64           = require("wirebaitlib.primitives.UInt64");
    newgt.Int64            = require("wirebaitlib.primitives.Int64");
    newgt.ProtoField       = require("wirebaitlib.dissector.ProtoField");
    newgt.Proto            = require("wirebaitlib.dissector.Proto").new;
    newgt.Field            = require("wirebaitlib.dissector.FieldExtractor").Field;
    newgt.ftypes           = newgt.ProtoField.ftypes;
    newgt.base             = newgt.ProtoField.base;
    newgt.__wirebait_state = createRunnerState(); --TODO: this is not used
    newgt.DissectorTable   = newgt.__wirebait_state.dissector_table;
    setfenv(dissector_chunk_func, newgt);

    --Loading the dissector the dissector by running dissector_chunk_func()
    __wirebait_state = newgt.__wirebait_state; --TODO: find a way to not need this to be part of the global environment
    dissector_chunk_func();

    ------------------------------------------------ private methods ---------------------------------------------------

    --[[ Given the Tvb of a packet, pretty prints the data into an array of strings. Each element in that array
         represents a "pretty" line, containing col_counts blocks of bytes_per_col bytes. If not provided
         byte_per_col = 8 and cols_count = 2, which are the values used in the example below:
            0E 07 DE 02 22 FC 03 19   75 5A 7F FF FF FF FF FF
            FF FF F2 F8 22 FD DD 04   FC E6 8A A6 80 00 00 00
            00 00 00 01 57 69 72 65   62 61
    ]]
    local function createPrettyArrayOfByteLines(tvb, bytes_per_col, cols_count)
        bytes_per_col = bytes_per_col or 8;
        cols_count    = cols_count or 2;

        if tvb:len() == 0 then
            return {"<empty>"}
        end

        local array_of_lines  = {};
        local single_line_str = "";
        for i=1,tvb:len() do
            single_line_str = single_line_str .. " " .. tvb(i-1,1):bytes():toHex();
            if i % bytes_per_col == 0 then
                if (i % (cols_count * bytes_per_col) == 0) or (i == tvb:len()) then
                    table.insert(array_of_lines, single_line_str)
                    single_line_str = ""
                else
                    single_line_str = single_line_str .. "  ";
                end
            end
        end

        return array_of_lines;
    end

    --[[Running the dissector at proto_handle.dissector on the data provided in packet_or_buffer. packet_or_buffer can
        either be a Packet or a Tvb representing packet data.]]
    local function runDissector(packet_or_buffer, proto_handle, packet_no)
        assert(packet_or_buffer and proto_handle and packet_no);
        assert(proto_handle == __wirebait_state.proto, "The proto handle found in the dissector table should match the proto handle stored in state.proto!");

        local packet = packet_or_buffer;
        local buffer = packet_or_buffer;
        if (Utils.typeof(packet_or_buffer) == "Packet") then
            buffer = packet:getData();
        else
            assert(Utils.typeof(packet_or_buffer) == "Tvb");
            packet = nil;
        end

        local root_tree = TreeItemClass.new(buffer);
        local result = proto_handle.dissector(buffer, __wirebait_state.packet_info, root_tree);
        if __wirebait_state.packet_info.desegment_len and __wirebait_state.packet_info.desegment_len > 0 then
            io.write("[ERROR] Your dissector requested TCP reassembly starting with frame# " .. packet_no .. ". This is not supported yet, each individual frame will be dissected separately.");
        end

        if packet then --print packet info if available (not available when dissecting HEX data)
            packet:printInfo(packet_no, __wirebait_state.packet_info.cols); io.write("\n");
        end

        local packet_bytes_lines = createPrettyArrayOfByteLines(buffer);
        local treeitems_array = __wirebait_state.packet_info.treeitems_array;
        local size = math.max(#packet_bytes_lines, #treeitems_array);
        for i=1,size do
            local bytes_str = string.format("%-50s",packet_bytes_lines[i] or "")
            local treeitem_str = treeitems_array[i] and treeitems_array[i].m_text or "";
            io.write(bytes_str .. "  |  " .. treeitem_str .. "\n");
        end
    end

    ------------------------------------------------ public methods ----------------------------------------------------

    --[[Running the loaded dissector on the pcap file at pcap_filetpah]]
    function dissector_runner:dissectPcap(pcap_filepath)
        assert(pcap_filepath, "DissectorRunner:dissectPcap() requires 1 argument: a path to a pcap file!");
        local pcap_reader = PcapReaderClass.new(pcap_filepath)
        local packet_no = 1;
        repeat
            local frame = pcap_reader:getNextEthernetFrame()
            if frame then
                local buffer = frame.ethernet.ipv4.udp.data or frame.ethernet.ipv4.tcp.data;
                if buffer then
                    assert(Utils.typeof(buffer) == "Tvb");
                    local proto_handle = nil;
                    if frame:getIPProtocol() == PROTOCOL_TYPES.UDP then
                        proto_handle = __wirebait_state.dissector_table.udp.port[frame:getSrcPort()] or __wirebait_state.dissector_table.udp.port[frame:getDstPort()];
                    else
                        assert(frame:getIPProtocol() == PROTOCOL_TYPES.TCP, "Unknown IP protocol '" .. tostring(frame:getIPProtocol()) .. "'");
                        proto_handle = __wirebait_state.dissector_table.tcp.port[frame:getSrcPort()] or __wirebait_state.dissector_table.tcp.port[frame:getDstPort()];
                    end
                    __wirebait_state.packet_info = PacketInfoClass.new(frame);
                    if proto_handle then
                        io.write("\n\n------------------------------------------------------------------------------------------------------------------------------[[\n\n");
                        runDissector(frame, proto_handle, packet_no);
                        io.write("]]------------------------------------------------------------------------------------------------------------------------------\n");
                    elseif not self.m_only_show_dissected_packets then
                        io.write("\n\n------------------------------------------------------------------------------------------------------------------------------[[\n");
                        frame:printInfo(packet_no, __wirebait_state.packet_info.cols);
                        io.write("]]------------------------------------------------------------------------------------------------------------------------------\n");
                    end
                end
            end
            packet_no = packet_no + 1;
        until frame == nil
    end

    --[[Running the loaded dissector on the provided hexadecimal string data]]
    function dissector_runner:dissectHexData(hex_data_str)
        io.write("\n\n------------------------------------------------------------------------------------------------------------------------------[[\n");
        io.write("Dissecting hexadecimal data (no pcap provided)\n\n");
        local buffer = TvbClass.new(ByteArrayClass.new(hex_data_str));
        runDissector(buffer, __wirebait_state.proto, 0);
        io.write("]]------------------------------------------------------------------------------------------------------------------------------\n");
    end

    return dissector_runner;
end

return DissectorRunnerClass;