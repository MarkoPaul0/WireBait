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

--[[
As far as I know, only 2 columns are modifiable: protocol and info.
An attempt to modify any other column will have no effect, and will NOT raise any error
c.f. [Wireshark Columns Wiki](https://wiki.wireshark.org/LuaAPI/Pinfo#Column)
]]

local MODIFIABLE_COLUMNS = {info=true, protocol=true};

function PacketInfoClass.new(packet)
    assert(packet, "Packet.Info.new() requires a Packet")
    local packet_info = {
        _struct_type = "PacketInfo",
        __pinfo = {
            __visited          = -1, --set if packet has already been visited
            __number           = -1, --packet number in the current file
            __len              = -1, --frame len
            __caplen           = -1, --captured frame len
            __abs_ts           = -1, --when packet was captured
            __rel_ts           = -1, --number of seconds since the beginning of the capture
            __delta_ts         = -1, --number of seconds since last packet
            __delta_dis_ts     = -1, --number of seconds since last displayed packet
            __curr_proto       = packet:protocol(), --protocol we are dissecting
            __can_desegment    = -1, --Set if this segment could be desegmented.
            __desegment_len    = -1, --Estimated number of additional bytes required for completing the PDU.
            __desegment_offset = -1, --Offset in the tvbuff at which the dissector will continue processing when next called
            __fragmented       = -1, --If the protocol is only a fragment
            __in_error_pkt     = -1, --we're inside an error pkt
            __match_uint       = -1, --Matched uint for calling subdissector from table
            __match_string     = -1, --Matched string for calling subdissector from table.
            __port_type        = -1, --Type of Port of .src_port and .dst_port
            __src_port         = packet:getSrcPort(), --Source Port of this Packet
            __dst_port         = packet:getDstPort(), --Destination Port of this Packet
            __dl_src           = -1, --Data Link Source Address of this Packet
            __dl_dst           = -1, --Data Link Destination Address of this Packet
            __net_src          = -1, --Network Layer Source Address of this Packet
            __net_dst          = -1, --Network Layer Destination Address of this Packet
            __src              = packet:getSrcIP(), --Source Address of this Packet
            __dst              = packet:getDstIP(), --Destination Address of this Packet
            __match            = -1, --Port/Data we are matching
        },
        columns = { --[[ c.f. [wireshark pinfo.cols](https://wiki.wireshark.org/LuaAPI/Pinfo) ]]
            __number               = ColumnClass.new(),
            __abs_time             = ColumnClass.new(),
            __utc_time             = ColumnClass.new(),
            __cls_time             = ColumnClass.new(),
            __rel_time             = ColumnClass.new(),
            __date                 = ColumnClass.new(),
            __utc_date             = ColumnClass.new(),
            __delta_time           = ColumnClass.new(),
            __delta_time_displayed = ColumnClass.new(),
            __src                  = ColumnClass.new(packet:getSrcIP()),
            __src_res              = ColumnClass.new(),
            __src_unres            = ColumnClass.new(),
            __dl_src               = ColumnClass.new(),
            __dl_src_res           = ColumnClass.new(),
            __dl_src_unres         = ColumnClass.new(),
            __net_src              = ColumnClass.new(),
            __net_src_res          = ColumnClass.new(),
            __net_src_unres        = ColumnClass.new(),
            __desegment_len        = ColumnClass.new(),
            __dst                  = ColumnClass.new(packet:getDstIP()),
            __dst_res              = ColumnClass.new(),
            __dst_unres            = ColumnClass.new(),
            __dl_dst               = ColumnClass.new(),
            __dl_dst_res           = ColumnClass.new(),
            __dl_dst_unres         = ColumnClass.new(),
            __net_dst              = ColumnClass.new(),
            __net_dst_res          = ColumnClass.new(),
            __net_dst_unres        = ColumnClass.new(),
            __src_port             = ColumnClass.new(tostring(packet:getSrcPort())),
            __src_port_res         = ColumnClass.new(),
            __src_port_unres       = ColumnClass.new(),
            __dst_port             = ColumnClass.new(tostring(packet:getDstPort())),
            __dst_port_res         = ColumnClass.new(),
            __dst_port_unres       = ColumnClass.new(),
            __protocol             = ColumnClass.new(packet:protocol(), --[[modifiable=]]true),
            __info                 = ColumnClass.new("", --[[modifiable=]]true),
            __packet_len           = ColumnClass.new(),
            __cumulative_bytes     = ColumnClass.new(),
            __direction            = ColumnClass.new(),
            __vsan                 = ColumnClass.new(),
            __tx_rate              = ColumnClass.new(),
            __rssi                 = ColumnClass.new(),
            __dce_call             = ColumnClass.new()
        },

        --TODO: move this somewhere else?
        treeitems_array = {}
    }

    packet_info.cols = packet_info.columns;
    --TODO: finish proper initialization
    packet_info.columns.__info:set(packet_info.__pinfo.__src_port .. " → " .. packet_info.__pinfo.__dst_port .. "  Len=" .. string.format("%d", packet:len()));

    ------------------------------------------------ metamethods -------------------------------------------------------

    --[[
        A user may col packet_info.cols.src_port, which will not
    ]]
    packet_info.columns.__index = function(self, key)
        return rawget(self, "__"..key);
    end

    packet_info.columns.__newindex = function(self, key, val)
      if not self[key] then
        error("PacketInfo has not column '" .. key .. "'");
      end
      self[key]:set(val);
        --columns cannot be replaced, so here we just do nothing and ignore the assignment
    end
    
    packet_info.__index = function(self, key)
        return rawget(self, "__pinfo")["__"..key];
    end

    packet_info.__newindex = function(self, key, val)
        if not self[key] then
            error("'__pinfo.__" ..  key .. "' does not exist!");
        end
        --TODO: only allow modifications of modifiable items
        self.__pinfo["__" .. key] = val;
    end

    setmetatable(packet_info.columns, packet_info.columns);
    setmetatable(packet_info, packet_info);

    return packet_info;
end

return PacketInfoClass;