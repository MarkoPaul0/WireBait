# WireBait [![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
Lua library to facilitate the development of [Wireshark](https://www.wireshark.org/) dissectors by enabling you to run them against pcap files without Wireshark.
[WireBait on Github](https://github.com/MarkoPaul0/WireBait)
## Requirements
  * You have a Lua interpreter 5.3
  * You have a Lua debugger (I like [ZeroBrane Studio](https://studio.zerobrane.com/))
  * You have a dissector and a pcap file to test it
  
Note that WireBait does not interact at all with Wireshark, so the Lua version displayed under 
*Wireshark > Help > About Wireshark* has nothing to to do with this.

## Quick start
Getting started takes less than a minute:
  1. Download **wirebait.lua**
  2. Add the following snippet of code on top of the script you want to run/debug. (Checkout the example [simple_dissector.lua](https://github.com/MarkoPaul0/WireBait/blob/master/example/simple_dissector.lua) to see how that looks)
```lua
    if disable_lua == nil and not _WIREBAIT_ON_ then  --disable_lua == nil checks if this script is being run from wireshark.
      local wirebait = require("wirebait");
      local dissector_tester = wirebait.plugin_tester.new({only_show_dissected_packets=true});
      dissector_tester:dissectPcap("path_to_your_pcap_file.pcap");
      return
    end
```
  3. Edit the code snippet to have your dissector read the pcap file you want.
  4. Execute your dissector script. Enjoy :smiley:
  
 ## Example
 If you run the **simple_dissector.lua** script with the provided **smp_sample.pcap** file, you should get the following output:
```
 ------------------------------------------------------------------------------------------------------------------------------[[
Frame# 1: UDP packet from 192.168.0.1:59121 to 255.255.255.255:7437
	 00 00 00 00 00 00 0B 24   02 AA 00 01 57 69 72 65	|	Simple Protocol
	 62 61 69 74 5C 30 00 00   00 00 00 00 00 00 00 00	|	└─ Header appendix :)
	 00 00 00 00 72 63 68 65   72 20 43 39 20 76 31 00	|	   └─ Sequence Number: 2852
	 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00	|	   └─ Type: 2
	 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00	|	   └─ Size: 170
	 00 00 00 00 00 00 00 31   2E 30 32 2E 36 35 2E 00	|	   └─ Urgent: 1
	 00 00 00 00 00 00 00 00   00 00 00 00 00 01 00 00	|	   └─ Username: Wirebait\0
	 00 01 00 00 00 02 00 00   00 02 00 00 00 00 00 00	|	   └─ Protofiel-less item
	 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00	|	
	 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00	|	
	 00 00 00 00 00 00 00 00   00 00 00 00 00       	|	
]]------------------------------------------------------------------------------------------------------------------------------
```

  In wireshark the same dissection would look like this:
  
  ![](example/smp_sample_in_wireshark.png)
  
## How does it work?
It simply exposes the [Wireshark Lua API](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html) ([or here](https://wiki.wireshark.org/LuaAPI)) and **attempts** to reproduce its behavior. Instead of displaying the dissected packet in a GUI, it prints a simple version of the tree in the console along with the payload in hexadecimal format.
A few notes about the current state of the project:
  * Only compatible with Lua 5.3
  * TCP reassembly is not supported
  * Only "*.pcap*" files are supported
  * Pcap files must be written in native byte order
  

# Licensing (c.f. LICENSE.txt)
WireBait for Wireshark is a lua package to help create Wireshark Dissectors
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
