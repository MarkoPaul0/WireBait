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

local ColumnClass = require("wirebaitlib.packet_info.Column");

--[[
    PacketInfoClass is meant to provide the functionality described in the Wireshark lua API documentation.
    [c.f. Wireshark Packet Information](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html)

    To instantiate a Wirebait PacketInfoClass, one needs to provide a Packet instance for which the info will be
    extracted.

    //Constructor
    <PacketInfoClass> PacketInfoClass.new(<Packet> packet)
]]
local PacketInfoClass = {};

function PacketInfoClass.new(packet)
    assert(packet, "Packet.Info.new() requires a Packet")
    local packet_info = {
        cols = { --[[ c.f. [wireshark pinfo.cols](https://wiki.wireshark.org/LuaAPI/Pinfo) ]]
            __number               = ColumnClass.new(),
            __abs_time             = ColumnClass.new(),
            __utc_time             = ColumnClass.new(),
            __cls_time             = ColumnClass.new(),
            __rel_time             = ColumnClass.new(),
            __date                 = ColumnClass.new(),
            __utc_date             = ColumnClass.new(),
            __delta_time           = ColumnClass.new(),
            __delta_time_displayed = ColumnClass.new(),
            __src                  = ColumnClass.new(),
            __src_res              = ColumnClass.new(),
            __src_unres            = ColumnClass.new(),
            __dl_src               = ColumnClass.new(),
            __dl_src_res           = ColumnClass.new(),
            __dl_src_unres         = ColumnClass.new(),
            __net_src              = ColumnClass.new(),
            __net_src_res          = ColumnClass.new(),
            __net_src_unres        = ColumnClass.new(),
            __dst                  = ColumnClass.new(),
            __dst_res              = ColumnClass.new(),
            __dst_unres            = ColumnClass.new(),
            __dl_dst               = ColumnClass.new(),
            __dl_dst_res           = ColumnClass.new(),
            __dl_dst_unres         = ColumnClass.new(),
            __net_dst              = ColumnClass.new(),
            __net_dst_res          = ColumnClass.new(),
            __net_dst_unres        = ColumnClass.new(),
            __src_port             = ColumnClass.new(),
            __src_port_res         = ColumnClass.new(),
            __src_port_unres       = ColumnClass.new(),
            __dst_port             = ColumnClass.new(),
            __dst_port_res         = ColumnClass.new(),
            __dst_port_unres       = ColumnClass.new(),
            __protocol             = ColumnClass.new(),
            __info                 = ColumnClass.new(),
            __packet_len           = ColumnClass.new(),
            __cumulative_bytes     = ColumnClass.new(),
            __direction            = ColumnClass.new(),
            __vsan                 = ColumnClass.new(),
            __tx_rate              = ColumnClass.new(),
            __rssi                 = ColumnClass.new(),
            __dce_call             = ColumnClass.new()
        },
        treeitems_array = {}
    }

    ------------------------------------------------ metamethods -------------------------------------------------------

    packet_info.cols.__index = function(self, key, val)
        return rawget(self, "__"..key);
    end

    packet_info.cols.__newindex = function(self, key, val)
        if not self["__"..key] then
            error("Column '" .. key .. "' does not exist!");
        end
        self["__"..key]:set(tostring(val));
    end

    setmetatable(packet_info.cols, packet_info.cols);

    --[[Initialization: note that it can only happen after metamethods are defined because the following init lines use
        __index and __newindex methods
    ]]
    packet_info.cols.src = packet:getSrcIP();
    packet_info.cols.dst = packet:getDstIP();
    packet_info.cols.src_port = packet:getSrcPort();
    packet_info.cols.dst_port = packet:getDstPort();
    packet_info.cols.protocol = packet:protocol();
    packet_info.cols.info = packet_info.cols.src_port .. " → " .. packet_info.cols.dst_port .. "  Len=" .. packet:len();

    return packet_info;
end

return PacketInfoClass;