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

local DissectorTable = {};

function DissectorTable.new()
    local dissector_table = {
        udp = { port = {} },
        tcp = { port = {} },
    }

    local function newPortTable()
        local port_table = {}

        function port_table:add(port, proto_handle)
            assert(port and proto_handle, "port and proto_handle cannot be nil!");
            local port_number = tonumber(port);
            assert(port_number >= 0 and port_number <= 65535, "A port must be between 0 and 65535!")
            self[port_number] = proto_handle;
        end

        return port_table;
    end

    dissector_table.udp.port = newPortTable();
    dissector_table.tcp.port = newPortTable();

    function dissector_table.get(path)
        local obj = dissector_table;
        path:gsub("%a+", function(split_path) obj = obj[split_path] end)
        return obj;
    end

    return dissector_table;
end

return DissectorTable;