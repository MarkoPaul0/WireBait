# WireBait

![Author](https://img.shields.io/badge/author-MarkoPaul0-red.svg?style=flat-square)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg?style=flat-square)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
![GitHub last commit](https://img.shields.io/github/last-commit/MarkoPaul0/WireBait.svg?style=flat-square&maxAge=300)
![GitHub (pre-)release](https://img.shields.io/github/release/MarkoPaul0/WireBait/all.svg?style=flat-square)
![GitHub (pre-)release](https://img.shields.io/github/commits-since/MarkoPaul0/WireBait/latest.svg?style=flat-square)
![Travis CI](https://travis-ci.com/MarkoPaul0/WireBait.svg?branch=master)
<!--
![GitHub release](https://img.shields.io/github/release/MarkoPaul0/WireBait/all.svg?style=flat-square)
-->

## **UPDATE: this repo is no longer supported. The concept is interesting, but bringing it to life would take time I don't want to allocate.** I'll leave this repo outthere for people to experiment.

Lua library to facilitate the development of [Wireshark](https://www.wireshark.org/) dissectors by enabling users to run them against packet data without Wireshark. The packet data can come from a hexadecimal string or a *.pcap* file.
The goal here is to provide a tool reducing development time when creating a new dissector.

**The following is an example of output produced when running your dissector with WireBait as a "standalone" script.**
  ```
------------------------------------------------------------------------------------------------------------------------------[[
No.         | Time                | Source            | Destination       | Protocol  | Length    | Info          
1           | 02:02:47.146635     | 192.168.0.1       | 255.255.255.255   | Demo      | 173       | 59121 → 7437  Len=32 

 0E 07 DE 02 22 FC 03 19   75 5A 7F FF FF FF FF FF  |  Demo Protocol
 FF 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00  |  └─ Unsigned integers:
                                                     |     └─ 8-bit uint: 14
                                                     |     └─ 16-bit uint: 2014
                                                     |     └─ 24-bit uint: 140028
                                                     |     └─ 32-bit uint: 52000090
                                                     |     └─ 64-bit uint: 9223372036854775807
]]------------------------------------------------------------------------------------------------------------------------------
  ```

## Content
[What does it do?](#what_does_it_do)<br/>
[Requirements](#requirements)<br/>
[Quick start](#quick_start)<br/>
[Examples](#examples)<br/>
[State of the project](#status)<br/>
[What's next and how to contribute?](#whats_next)<br/>
[Licensing](#licensing)<br/>


<a name="what_does_it_do"/>

## What does it do?
It simply exposes the [Wireshark Lua API](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html) ([or here](https://wiki.wireshark.org/LuaAPI)) and attempts to reproduce its behavior. As a result, your script becomes "self sufficient" and you can execute it directly and without Wireshark. If you provide it with some data, it will print a text version of the dissection tree along with the payload in hexadecimal format. **Now you can make changes to your dissector and see the effects immediately without leaving your Lua IDE!**

<a name="requirements"/>

## Requirements
* You have a Lua interpreter 5.2 or above 
* You have a dissector and data to test it (hex string or pcap file)
* You have a Lua debugger (I like [ZeroBrane Studio](https://studio.zerobrane.com/)) [only a requirement for step by step debugging]
  
Note that WireBait does not interact at all with Wireshark.

<a name="quick_start"/>

## Quick start
Getting started takes less than a minute:
  1. Make sure your Lua interpreter is 5.2 (in **Zerobrane Studio** go to **Project > Lua Interpreter** and select **Lua 5.2**)
  2. Add the **wirebaitlib/** directory to your Lua path
  3. Add the following snippet of code on top of the dissector you want to run/debug:
```lua
if disable_lua == nil and enable_lua == nil and not _WIREBAIT_ON_ then
  local wirebait = require("wirebaitlib");
  local dissector_tester = wirebait.new({only_show_dissected_packets=true});
  dissector_tester:dissectHexData("72ABE636AFC86572") -- To dissect hex data from a string (no pcap needed) 
  dissector_tester:dissectPcap("path_to_your_pcap_file.pcap") -- To dissect packets from a pcap file
  return
end
```
  4. Edit the code snippet and decide if your dissector should read *hexadecimal data* **and/or** a *pcap file* of your choice. Note that you can add this snippet in a file other than your dissector file. In this case you'll have to add an additional argument in the constructor of the dissector tester, specifying the path to your dissector file, just like so:
  ```lua
  local dissector_tester = wirebait.new({dissector_filepath="path_to_your_dissector.lua", only_show_dissected_packets=true});
  ```
  5. Execute your dissector script. Enjoy :smiley: **And please, feel free to give me feedback!**
  
 <a name="examples"/>
 
 ## Example 1 Dissecting data from a hexadecimal string
  If you run the example dissector script **[demo_dissector.lua](example/demo_dissector.lua)**, which dissects the data provided as an hexadecimal string, you should get the following output:
  ```
------------------------------------------------------------------------------------------------------------------------------[[
Dissecting hexadecimal data (no pcap provided)

 0E 07 DE 02 22 FC 03 19   75 5A 7F FF FF FF FF FF  |  Demo Protocol
 FF FF F2 F8 22 FD DD 04   FC E6 8A A6 80 00 00 00  |  └─ Unsigned integers:
 00 00 00 01 57 69 72 65   62 61 69 74 00 62 79 20  |     └─ 8-bit uint: 14
 4D 61 72 6B 6F 50 61 75   6C 30 00 00 AA BB CC 11  |     └─ 16-bit uint: 2014
 22 33 C0 A8 0E 1C AB CD   EF 12 34 56 78 90 AB CD  |     └─ 24-bit uint: 140028
 EF 12 34 56 78 90 00 00   00 00 00 00 00 00 00 00  |     └─ 32-bit uint: 52000090
 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00  |     └─ 64-bit uint: 9223372036854775807
 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00  |  └─ Signed integers:
 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00  |     └─ 8-bit int: -14
 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00  |     └─ 16-bit int: -2014
 00 00 00 00 00 00 00 00   00 00 00 00 00           |     └─ 24-bit int: -140028
                                                     |     └─ 32-bit int: -52000090
                                                     |     └─ 64-bit int: -9223372036854775807
                                                     |  └─ Strings:
                                                     |     └─ String: Wirebait
                                                     |     └─ Stringz: Wirebait
                                                     |  └─ Other types:
                                                     |     └─ bytes: aabbcc112233c0a80e1cabcdef1234567890abcdef1234567890...
                                                     |     └─ ethernet: aa:bb:cc:11:22:33
                                                     |     └─ IPv4: 192.168.14.28
                                                     |     └─ GUID: abcdef12-3456-7890-abcd-ef1234567890
]]------------------------------------------------------------------------------------------------------------------------------
  ```
**In wireshark the same dissection would look like this:**

![](example/screenshots/demo_in_wireshark.png)

**Something to note is that the hex string only contains the UDP (or TCP) payload**, i.e. only the data to be dissected. No need to worry about making up ethernet, IP, or TCP/UDP headers.

 ## Example 2 Dissecting data from a *.pcap* file
  If you run the example dissector script **[demo_dissector2.lua](example/demo_dissector2.lua)**, which dissects the same data as in the first example but provided by the **[demo.pcap](example/captures/demo.pcap)** file, you should get the same dissection output. One difference is that you will also get packet information that is provided by ethernet, IP, and TCP/UDP headers:
 ```
------------------------------------------------------------------------------------------------------------------------------[[
No.         | Time                | Source            | Destination       | Protocol  | Length    | Info          
1           | 02:02:47.146635     | 192.168.0.1       | 255.255.255.255   | Demo      | 173       | 59121 → 7437  Len=173 

 0E 07 DE 02 22 FC 03 19   75 5A 7F FF FF FF FF FF  |  Demo Protocol
 FF FF F2 F8 22 FD DD 04   FC E6 8A A6 80 00 00 00  |  └─ Unsigned integers:
 .......<trimmed output, same as example 1>
 ```

<a name="status"/>

## State of the project
A few notes about the current state of the project:
  * TCP reassembly is not supported
  * Only "*.pcap*" files are supported
  * Pcap files must be written in native byte order
  
For more information you can check what I'm up to in the [Project section](https://github.com/MarkoPaul0/WireBait/projects/1).
  
<a name="whats_next"/>

## What's next and how to contribute?
Right now I would like to collect feedback from Wireshark users. People who already have Lua dissectors can really help by running their dissectors using Wirebait. I would really appreciate any form of feedback about this tool.

I think - *without having collected feedback yet* - the next logical step is to **expand Wirebait to enable users to unit test their dissectors**. The clear cut specifications of protocol definitions are in my opinion a school book example of when unit test driven development makes sense. With unit tests, any protocol or dissector update can be tackled quicly while reducing the risk of introducing new bugs.

<a name="licensing"/>

## Licensing 
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
**(Checkout the full [license](LICENSE.txt))**
