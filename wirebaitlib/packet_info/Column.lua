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

--[[
    ColumnClass is meant to provide the functionality of the Column type described in the Wireshark lua API
    documentation.
    [c.f. Wireshark ColumnClass](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Column)

    To instantiate a Wirebait Column, one needs to provide a string corresponding to the column info.

    //Constructor
    <ColumnClass> ColumnClass.new(<string> txt)
]]
local ColumnClass = {};

function ColumnClass.new(text, modifiable)
    assert(not text or type(text) == "string");
    local column = {
        _struct_type = "Column";
        m_text = text or "";
        m_fence_idx = 0;
        m_modifiable = modifiable or false; --most columns are not modifiable
    };

    ------------------------------------------------ metamethods -------------------------------------------------------
    
    function column:__tostring()
        return self.m_text;
    end

    function column.__concat(op1, op2)
        return op1.m_text, op2.m_text;
    end

    ----------------------------------------------- public methods -----------------------------------------------------

    function column:set(text)
        if not self.m_modifiable then
            return;
        end
        if self.m_fence_idx > 0 then
            assert(self.m_fence_idx <= self.m_text:len());
            self.m_text = self.m_text:sub(1, self.m_fence_idx) .. text;
        else
            self.m_text = text;
        end
    end

    function column:clear()
        if not self.m_modifiable then
            return;
            end
        if self.m_fence_idx > 0 then
            assert(self.m_fence_idx <= self.m_text:len());
            self.m_text = self.m_text:sub(1, self.m_fence_idx);
        else
            self.m_text = "";
        end
    end

    function column:append(text)
        if not self.m_modifiable then
            return;
        end
        self.m_text = self.m_text .. text;
    end

    function column:prepend(text)
        if not self.m_modifiable then
            return;
        end
        if self.m_fence_idx > 0 then
            assert(self.m_fence_idx <= self.m_text:len());
            self.m_text = self.m_text:sub(1, self.m_fence_idx) .. text .. self.m_text:sub(self.m_fence_idx + 1, self.m_text:len())
        else
            self.m_text = text .. self.m_text;
        end
    end

    function column:fence()
        if not self.m_modifiable then
            return;
        end
        self.m_fence_idx = self.m_text:len();
    end

    function column:clear_fence()
        if not self.m_modifiable then
            return;
        end
        self.m_fence_idx = 0;
    end

    setmetatable(column, column);
    return column;
end

return ColumnClass;