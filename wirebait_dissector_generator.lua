
--[[
    WireBait for Wireshark is a lua package to help write Wireshark 
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

-- !! IGNORE THIS FILE FOR NOW!
--[[
local function verifyArgsType(...)  --TODO: ability to check optional args
	level = 2;
	i = 1;
	while true do
		expected_type = select(i, ...);
		if not expected_type then break end;
			var_name, var_val =  debug.getlocal(level,i);
			assert(type(var_val) == expected_type, "\nFunction " .. debug.getinfo(2).name .."() expected arg #".. i .." to be of type '" .. tostring(expected_type) .. "' but got '" .. type(var_val) .. "'!")
			i = i + 1;
		end
	end


-- # Wirebait Field
	local function newWirebaitField(filter, name, size, ws_type_key, --[[optional]]display_val_map)
		verifyArgsType('string', 'string', 'number', 'string')
		local wb_field = { --private data
			m_filter = filter,
			m_name = name,
			m_size = size,
			m_type = ws_type_key,
			m_wireshark_field = ProtoField[ws_type_key](filter, name, size, base, display_val_map);
		}

		local getFilter = function()
			return wb_field.m_filter;
		end

		local getName = function()
			return wb_field.m_name;
		end

		local getSize = function()
			return wb_field.m_size
		end

		local getWiresharkProtofield = function()
			return wb_field.m_wireshark_field;
		end

		local getType = function()
			return wb_field.m_type;
		end

		local pulic_wirebait_field_interface = {
			filter = getFilter,
			name = getName,
			size = getSize,
			wsProtofield = getWiresharkProtofield,
			type = getType,
		};

		return pulic_wirebait_field_interface;
	end


	local function newWirebaitTree(ws_tree, buffer, position)
		local wb_tree = { --private data
			m_ws_tree = ws_tree;
			m_buffer = buffer;
			m_start_position = position or 0;
			m_position = (position or 0), --+ (size or 0);
		}

		local getParent = function()
			return wb_tree.m_parent;
		end

		local getWiresharkTree = function ()
			return wb_tree.m_ws_tree;
		end

		local getBuffer = function()
			return wb_tree.m_buffer;
		end

		local getPosition = function()
			return wb_tree.m_position;
		end

		local getLength = function()
			assert(wb_tree.m_position >= wb_tree.m_start_position);
			return wb_tree.m_position - wb_tree.m_start_position;
		end

		local skip = function(self, byte_count) --skip only affects the current tree and cannot go beyon the end_position
			--if not wb_tree.m_is_root then
			--   self:parent():skip(byte_count);
			--end
			assert(wb_tree.m_position + byte_count <= wb_tree.m_end_position , "Trying to skip more bytes than available in buffer managed by wirebait tree!")
			wb_tree.m_position = wb_tree.m_position + byte_count;
		end

		local skipTo = function(self, position)
			assert(position <= wb_tree.m_end_position , "Trying to skip more bytes than available in buffer managed by wirebait tree!")
			wb_tree.m_position = position;
		end

		local resetHighlight = function(self, length, relative_offset)
			local L = length or 0;
			local R = relative_offset or 0;
			--TODO: do something witht the relative offset
			wb_tree.m_ws_tree:set_length(length);
		end

		local addHeader = function(self, header_str, byte_count) 
			wb_tree.m_ws_tree:add(
			end

			return {
				getParent,
				getWiresharkTree,
				getBuffer,
				getPosition,
				getLength,
				skip,
				skipTo,
				resetHighlight
			}
		end

-- # wirebait dissector
		local function newDissectorGenerator()
			local wirebait_dissector = {
				--m_name = name; --e.g "Dummy Transfer Protocol"
				--m_abbr = abbr; --abbreviation "DTP"
				m_wb_fields = {}; --fields that
				m_wb_dissection_func = {};
			}

			--local public_wb_dissector = {
			--    __is_wirebait_struct = true, --all wirebait data should have this flag so as to know their type
			--    __wirebait_type_name = "WirebaitDissector",
			--}
			local byte_size_by_type = {
				["uint8"] = 1;
				["uint16"] = 2;
				["uint32"] = 4;
				["uint64"] = 8;
			}

			local registerField = function(ftype, name, filter, --[[optional]] display_value_map)
				local wirebait_field = newWirebaitField(filter, name, byte_size_by_type[ftype], ftype, diplay_value_map);
				wirebait_dissector.m_wb_fields[#wirebait_dissector.m_wb_fields] = wirebait_field;
			end

			local generateWiresharkDissector = function(name, abbr)
				local ws_dissector = Proto(abbr, name);
				ws_dissector.fields = {};
				for i,wb_field in ipairs(wirebait_dissector.m_wb_fields) do
					ws_dissector.fields["f_" .. wb_field.getName] = wb_field.getWiresharkProtofield()
				end
				ws_dissector.fields["f_wb_tree_header_"] = ProtoField.string(abbr .. "_tr_hdr_", "Tree Header");
				ws_dissector.dissector = function(ws_buffer, ws_info, ws_tree) 
					--TODO: actually make these wb elements
					local wb_tree = newWirebaitTree(ws_tree, ws_buffer);
					wirebait_dissector.m_wb_dissection_func(wb_buffer, ws_info, wb_tree);
				end
				return ws_dissector;
			end

			local setDissectionFunction = function(wb_dissection_func)
				--todo check the func is a func
				wirebait_dissector.m_wb_dissection_func = wb_dissection_func;
			end

			return {
				registerField = registerField,
				setDissectionFunction = setDissectionFunction,
				generateDissector = generateWiresharkDissector,
			}
		end


--[[ Using a function to create the wirebait module so that it can have 
private state data ( 1 dissector per wirebait, and wirebait keeps track of protofields
so as to register them automatically)
]]--
		local function publicWirebaitInterface() 
			local wirebait = { --wirebait state data which needs to be private
				m_created_proto_fields = {};
				m_size = 0,
				m_dissector = nil
			}

			function wirebait.createProtofield(filter, name, size, ws_protofield)
				local new_pf = newWirebaitField(filter, name, size, ws_protofield)
				wirebait.m_created_proto_fields[wirebait.m_size] = new_pf
				wirebait.m_size = wirebait.m_size + 1;
				return new_pf
			end

			function wirebait.createTreeitem(arg1, arg2, ...)
				return newWirebaitTree(wirebait.m_created_proto_fields, arg1, arg2, unpack({...}));
			end

			function wirebait.createDissectorSingleton(name, abbrev_name)
				--checks('string', 'string');
				if not wirebait.m_dissector then
					wirebait.m_dissector = Proto(abbrev_name, name);
				else
					return wirebait.m_dissector;
				end
			end

			function getCreatedProtofieldCount()
				return wirebait.m_size;
			end

			return { --All functions available in wirebait package are named here
				field = { new = wirebait.createProtofield, count = getCreatedProtofieldCount },
				tree = { new = wirebait.createTreeitem },
				--dissector = { newSingleton = wirebait.createDissectorSingleton },
				dissector = { new = newDissectorGenerator},
			}
		end

		wirebait = publicWirebaitInterface() 
		return wirebait
]]--
