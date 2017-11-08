--[[
    lua code that mocks wireshark lua api to test wirebait
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

local wireshark_mock = { Protofield = {}, treeitem = {}, buffer = {}, base = { DEC = {} }};

function wireshark_mock.Protofield.new(name, abbr, _type)
    assert(name and abbr and _type, "Protofiled argument should not be nil!")
    local protofield = {
        m_name = name;
        m_abbr = abbr;
        m_type = _type;
    }

    return protofield;
end

function wireshark_mock.treeitem.new() 
    local treeitem = {
        m_length = 0;
        m_subtrees = {};
        m_subtrees_count = 0;
    }

    function treeitem:set_len(length)
        self.m_length = length;
    end

    function treeitem:add(protofield)
        print("Added protofield " .. protofield.m_name .. ".");
        index = self.m_subtrees_count;
        self.m_subtrees[index] = { proto_field = protofield, treeitem = wireshark_mock.treeitem.new() };
        self.m_subtrees_count = self.m_subtrees_count + 1;
        return self.m_subtrees[index].treeitem;
    end

    return treeitem;
end

function wireshark_mock.buffer.new(data_as_hex_string)
    assert(type(data_as_hex_string) == 'string', "Buffer should be based on an hexadecimal string!")
    assert(string.len(data_as_hex_string:gsub('%X','')) > 0, "String should be hexadecimal!")
    assert(string.len(data_as_hex_string) % 2 == 0, "String has its last byte cut in half!")

    local buffer = {
        m_data_as_hex_str = data_as_hex_string;
    }

    function buffer:len()
        return string.len(self.m_data_as_hex_str)/2;
    end
    
    function hexStringToUint64(hex_str)
        assert(#hex_str > 0, "Requires strict positive number of bytes!");
        assert(#hex_str <= 16, "Cannot convert more thant 8 bytes to an int value!");
        hex_str = string.format("%016s",hex_str) --left pad with zeros
        return tonumber(hex_str,16);
    end
    
    function le_hexStringToUint64(hex_str) --little endian version
        assert(#hex_str > 0, "Requires strict positive number of bytes!");
        assert(#hex_str <= 16, "Cannot convert more thant 8 bytes to an int value!");
        hex_str = string.format("%-16s",hex_str):gsub(" ","0") --right pad with zeros
        le_string = "";
        byte_size=#hex_str/2
        for i=1,byte_size do
           le_string = hex_str:sub(2*i-1,2*i) .. le_string;
        end
        return tonumber(le_string,16);
    end

    function buffer:le_uint()
        size = math.min(#self.m_data_as_hex_str,8)
        return le_hexStringToUint64(string.sub(self.m_data_as_hex_str,0,size));
    end

    function buffer:le_uint64()
        size = math.min(#self.m_data_as_hex_str,16)
        return le_hexStringToUint64(string.sub(self.m_data_as_hex_str,0,size));
    end;
    
    function buffer:uint()
        size = math.min(#self.m_data_as_hex_str,8)
        return hexStringToUint64(string.sub(self.m_data_as_hex_str,0,size));
    end

    function buffer:uint64()
        size = math.min(#self.m_data_as_hex_str,16)
        return hexStringToUint64(string.sub(self.m_data_as_hex_str,0,size));
    end;

    function buffer:string()
        str = ""
        for i=1,self:len()-1 do
            byte_ = self.m_data_as_hex_str:sub(2*i-1,2*i)
            str = str .. string.char(tonumber(byte_, 16))
        end
        return str
    end
    
    function buffer:stringz()
        str = ""
        for i=1,self:len()-1 do
            byte_ = self.m_data_as_hex_str:sub(2*i-1,2*i)
            if byte_ == '00' then
                return str
            end
            str = str .. string.char(tonumber(byte_, 16))
        end
        return str
    end
    
    function buffer:__call(start, length) --allows buffer to be called as a function 
        assert(start >= 0, "Start position is positive!");
        assert(length > 0, "Length is strictly positive!");
        assert(start + length <= self:len(), "Index get out of bounds!")
        return wireshark_mock.buffer.new(string.sub(self.m_data_as_hex_str,2*start+1, 2*(start+length)))            
    end
    
    function buffer:__tostring()
       return "[buffer: 0x" .. self.m_data_as_hex_str .. "]";
    end
    setmetatable(buffer, buffer)
    
    return buffer;
end

--mapping diffent types to the same mock constructor
wireshark_mock.Protofield.uint8 = wireshark_mock.Protofield.new;
wireshark_mock.Protofield.uint16 = wireshark_mock.Protofield.new;
wireshark_mock.Protofield.uint32 = wireshark_mock.Protofield.new;
wireshark_mock.Protofield.uint64 = wireshark_mock.Protofield.new;
wireshark_mock.Protofield.string = wireshark_mock.Protofield.new;

function wireshark_mock.setupWiresharkEnvironment() --sets up variable in current scope
    base = wireshark_mock.base;
    Protofield = wireshark_mock.Protofield;
end

return wireshark_mock;


