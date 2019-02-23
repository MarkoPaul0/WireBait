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

local DissectorTable = require("wirebaitlib.dissector.DissectorTable");
local treeitem       = require("wirebaitlib.dissector.TreeItem");
local Tvb            = require("wirebaitlib.packet_data.Tvb");
local ByteArray      = require("wirebaitlib.primitives.ByteArray");
local PcapReaderLib  = require("wirebaitlib.packet_data.PcapReader");

local PacketInfo     = require("wirebaitlib.packet_info.PacketInfo");
local utils          = require("wirebaitlib.primitives.Utils");

local RunnerState = {};

--TODO: duplicate with Packet.lua
local PROTOCOL_TYPES = {
    IPV4 = 0x800,
    UDP  = 0x11,
    TCP  =  0x06
};

function RunnerState.new()
  local runner_state = {
    dissector_filepath = nil,
    proto = nil,
    packet_info = { --TODO should be reset after each packet
      cols={},
      treeitems_array = {} --treeitems are added to that array so they can be displayed after the whole packet is dissected
    },
    dissector_table = {
      udp = { port = nil },
      tcp = { port = nil }
    }
  }
  
  function runner_state:clear()
    self.dissector_filepath = nil;
    self.proto = nil;
    self.packet_info.cols = {};
    self.packet_info.treeitems_array = {};
    self.dissector_table.udp = { port = nil };
    self.dissector_table.tcp = { port = nil };
  end
  
  return runner_state;
end

local DissectorRunner = {};

function DissectorRunner.new(options_table) --[[options_table uses named arguments]] --TODO: document a comprehensive list of named arguments
    options_table = options_table or {};
    local plugin_tester = {
        m_dissector_filepath = options_table.dissector_filepath or arg[0], --if dissector_filepath is not provided, takes the path to the script that was launched
        m_only_show_dissected_packets = options_table.only_show_dissected_packets or false
    };

    state = RunnerState.new();

    --Setting up the environment before invoking dofile() on the dissector script
    local dofile_func = loadfile(plugin_tester.m_dissector_filepath);

    local newgt = {};
    setmetatable(newgt, {__index = _G}) -- have the new environment inherits from the current one to garanty access to standard functions
    newgt.state.dissector_table = DissectorTable.new();
    newgt._WIREBAIT_ON_ = true;

    newgt.UInt64     = require("wirebaitlib.primitives.UInt64");
    newgt.Int64      = require("wirebaitlib.primitives.Int64");
    newgt.ProtoField = require("wirebaitlib.dissector.ProtoField");
    newgt.Proto      = require("wirebaitlib.dissector.Proto").new;
    newgt.Field      = require("wirebaitlib.dissector.FieldExtractor").Field;
    --newgt.state      = state; --TODO: review this

    newgt.ftypes = newgt.ProtoField.ftypes;
    newgt.base = newgt.ProtoField.base;
    newgt.DissectorTable = newgt.state.dissector_table;



    if not dofile_func then
        error("File '" .. plugin_tester.m_dissector_filepath .. "' could not be found, or you don't have permissions!");
    end
    setfenv(dofile_func, newgt);
    dofile_func();

    local function formatBytesInArray(buffer, bytes_per_col, cols_count) --[[returns formatted bytes in an array of lines of bytes. --TODO: clean this up]]
        if buffer:len() == 0 then
            return {"<empty>"}
        end
        bytes_per_col = bytes_per_col or 8;
        cols_count = cols_count or 2;
        local array_of_lines = {};
        local str = "";
        for i=1,buffer:len() do
            str = str .. " " .. tostring(buffer(i-1,1));
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


    local function runDissector(buffer, proto_handle, packet_no, packet)
        assert(buffer and proto_handle and packet_no);
        local root_tree = treeitem.new(buffer);
        assert(proto_handle == state.proto, "The proto handle found in the dissector table should match the proto handle stored in state.proto!");
        local result = proto_handle.dissector(buffer, state.packet_info, root_tree);
        if state.packet_info.desegment_len and state.packet_info.desegment_len > 0 then
            io.write(string.rep("WARNING! (please read below)\n", 4));
            io.write("##################    WRIEBAIT DOES NOT SUPPORT TCP REASSEMBLY YET!!!!!!   ############################################\n");
            io.write("Your dissector requested TCP reassembly starting with frame# " .. packet_no .. ". This is not supported yet, each individual frame will be dissected separately.");
            io.write("\n\n.");
        end
        if packet then
            packet:printInfo(packet_no, state.packet_info.cols); io.write("\n");
        end
        local packet_bytes_lines = formatBytesInArray(buffer);
        local treeitems_array = state.packet_info.treeitems_array;
        local size = math.max(#packet_bytes_lines, #treeitems_array);
        for i=1,size do
            local bytes_str = string.format("%-50s",packet_bytes_lines[i] or "")
            local treeitem_str = treeitems_array[i] and treeitems_array[i].m_text or "";
            io.write(bytes_str .. "  |  " .. treeitem_str .. "\n");
        end
    end

    function plugin_tester:dissectPcap(pcap_filepath)
        assert(pcap_filepath, "plugin_tester:dissectPcap() requires 1 argument: a path to a pcap file!");
        local pcap_reader = PcapReaderLib.new(pcap_filepath)
        local packet_no = 1;
        repeat
            local frame = pcap_reader:getNextEthernetFrame()
            if frame then
                local buffer = frame.ethernet.ipv4.udp.data or frame.ethernet.ipv4.tcp.data;
                if buffer then
                    assert(utils.typeof(buffer) == "Tvb");
                    local proto_handle = nil;
                    if frame:getIPProtocol() == PROTOCOL_TYPES.UDP then
                        proto_handle = state.dissector_table.udp.port[frame:getSrcPort()] or state.dissector_table.udp.port[frame:getDstPort()];
                    else
                        assert(frame:getIPProtocol() == PROTOCOL_TYPES.TCP)
                        proto_handle = state.dissector_table.tcp.port[frame:getSrcPort()] or state.dissector_table.tcp.port[frame:getDstPort()];
                    end
                    state.packet_info = PacketInfo.new(frame);
                    if proto_handle then
                        io.write("\n\n------------------------------------------------------------------------------------------------------------------------------[[\n\n");
                        runDissector(buffer, proto_handle, packet_no, frame);
                        io.write("]]------------------------------------------------------------------------------------------------------------------------------\n");
                    elseif not self.m_only_show_dissected_packets then
                        io.write("\n\n------------------------------------------------------------------------------------------------------------------------------[[\n");
                        frame:printInfo(packet_no, state.packet_info.cols);
                        io.write("]]------------------------------------------------------------------------------------------------------------------------------\n");
                    end
                end
            end
            packet_no = packet_no + 1;
        until frame == nil
    end

    function plugin_tester:dissectHexData(hex_data)
        io.write("\n\n------------------------------------------------------------------------------------------------------------------------------[[\n");
        io.write("Dissecting hexadecimal data (no pcap provided)\n\n");
        local buffer = Tvb.new(ByteArray.new(hex_data));
        runDissector(buffer, state.proto, 0);
        io.write("]]------------------------------------------------------------------------------------------------------------------------------\n");
    end

    return plugin_tester;
end

return DissectorRunner;