# IDA Pro processor module for RSSB

Proof of concept implementation of an IDA Processor module for *Reverse Subtract
and Skip if Borrow* (RSSB) machines.
Written for IDA Pro 7 and tested on IDA Pro 7.1.

This module was written to solve *Suspicious Floppy Disk*---the last challenge---of [Flare-On 2018](http://flare-on.com/) reverse engineering competition.
The aim of this IDA processor is to translate `rssb` instructions to an higher
level interpretation. You can find a quick explanation of the implemented macro
at [this blog post](https://emanuelecozzi.net/posts/ctf/flareon-2018-challenge-12-subleq-rssb-writeup).

Please, take it as it is and bear in mind this processor is strongly built on
top of the RSSB macros created by the challenge author.

Content:

- **rssb-ida.py**, IDA processor module. Move it to `/<IDA installation
path>/procs/`
- **rssb-emu.py**, an Rssb emulator written in Python
- **flareon2018-ch12.rssb**, the Rssb payload extracted from last challenge of
Flare-On 2018
