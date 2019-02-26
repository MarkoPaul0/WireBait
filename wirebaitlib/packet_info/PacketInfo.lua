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
            visited          = -1, --set if packet has already been visited
            number           = -1, --packet number in the current file
            len              = -1, --frame len
            caplen           = -1, --captured frame len
            abs_ts           = -1, --when packet was captured
            rel_ts           = -1, --number of seconds since the beginning of the capture
            delta_ts         = -1, --number of seconds since last packet
            delta_dis_ts     = -1, --number of seconds since last displayed packet
            curr_proto       = packet:protocol(), --protocol we are dissecting
            can_desegment    = -1, --Set if this segment could be desegmented.
            desegment_len    = -1, --Estimated number of additional bytes required for completing the PDU.
            desegment_offset = -1, --Offset in the tvbuff at which the dissector will continue processing when next called
            fragmented       = -1, --If the protocol is only a fragment
            in_error_pkt     = -1, --we're inside an error pkt
            match_uint       = -1, --Matched uint for calling subdissector from table
            match_string     = -1, --Matched string for calling subdissector from table.
            port_type        = -1, --Type of Port of .src_port and .dst_port
            src_port         = packet:getSrcPort(), --Source Port of this Packet
            dst_port         = packet:getDstPort(), --Destination Port of this Packet
            dl_src           = -1, --Data Link Source Address of this Packet
            dl_dst           = -1, --Data Link Destination Address of this Packet
            net_src          = -1, --Network Layer Source Address of this Packet
            net_dst          = -1, --Network Layer Destination Address of this Packet
            src              = packet:getSrcIP(), --Source Address of this Packet
            dst              = packet:getDstIP(), --Destination Address of this Packet
            match            = -1, --Port/Data we are matching
        },
        cols = { --[[ c.f. [wireshark pinfo.cols](https://wiki.wireshark.org/LuaAPI/Pinfo) ]]
            number               = ColumnClass.new(),
            abs_time             = ColumnClass.new(),
            utc_time             = ColumnClass.new(),
            cls_time             = ColumnClass.new(),
            rel_time             = ColumnClass.new(),
            date                 = ColumnClass.new(),
            utc_date             = ColumnClass.new(),
            delta_time           = ColumnClass.new(),
            delta_time_displayed = ColumnClass.new(),
            src                  = ColumnClass.new(packet:getSrcIP()),
            src_res              = ColumnClass.new(),
            src_unres            = ColumnClass.new(),
            dl_src               = ColumnClass.new(),
            dl_src_res           = ColumnClass.new(),
            dl_src_unres         = ColumnClass.new(),
            net_src              = ColumnClass.new(),
            net_src_res          = ColumnClass.new(),
            net_src_unres        = ColumnClass.new(),
            desegment_len        = ColumnClass.new(),
            dst                  = ColumnClass.new(packet:getDstIP()),
            dst_res              = ColumnClass.new(),
            dst_unres            = ColumnClass.new(),
            dl_dst               = ColumnClass.new(),
            dl_dst_res           = ColumnClass.new(),
            dl_dst_unres         = ColumnClass.new(),
            net_dst              = ColumnClass.new(),
            net_dst_res          = ColumnClass.new(),
            net_dst_unres        = ColumnClass.new(),
            src_port             = ColumnClass.new(tostring(packet:getSrcPort())),
            src_port_res         = ColumnClass.new(),
            src_port_unres       = ColumnClass.new(),
            dst_port             = ColumnClass.new(tostring(packet:getDstPort())),
            dst_port_res         = ColumnClass.new(),
            dst_port_unres       = ColumnClass.new(),
            protocol             = ColumnClass.new(packet:protocol(), --[[modifiable=]]true),
            info                 = ColumnClass.new("", --[[modifiable=]]true),
            packet_len           = ColumnClass.new(),
            cumulative_bytes     = ColumnClass.new(),
            direction            = ColumnClass.new(),
            vsan                 = ColumnClass.new(),
            tx_rate              = ColumnClass.new(),
            rssi                 = ColumnClass.new(),
            dce_call             = ColumnClass.new()
        },
        columns = cols,

        --TODO: move this somewhere else?
        treeitems_array = {}
    }
    
    --TODO: finish proper initialization
    packet_info.cols.info:set(packet_info.__pinfo.src_port .. " → " .. packet_info.__pinfo.dst_port .. "  Len=" .. packet:len());

    ------------------------------------------------ metamethods -------------------------------------------------------

    --[[
        A user may col packet_info.cols.src_port, which will not
    ]]
    packet_info.cols.__index = function(self, key)
        return rawget(self, "__"..key);
    end

    packet_info.cols.__newindex = function(self, key, val)
        --columns cannot be replaced, so here we just do nothing and ignore the assignment
    end
    
    packet_info.__index = function(self, key)
        if key == "cols" then
          return self.cols;
        end
        return rawget(self, "__pinfo")[key];
    end

    packet_info.__newindex = function(self, key, val)
        if not self.__pinfo[key] then
            error("'pinfo." .. key .. "' does not exist!");
        end
        --TODO: only allow modifications of modifiable items
        self.__pinfo[key] = val;
    end

    setmetatable(packet_info.cols, packet_info.cols);
    setmetatable(packet_info, packet_info);

    return packet_info;
end

return PacketInfoClass;