

This program links with PcapPlusPlus and hiredis to
parse out Redis command from PCAP files. I had pcaps
with millions of TCP connections and I need the times
for each connection. See the RedisStreams.cpp file
for more details.

----
Building
---
`./build.sh` 

You need PcapPlusPlus, hiredis, libpcap, and libpthread. 

Compiles with g++ 5.4 just fine.

---
Running
---

Normally, I run something like:
`./RedisStreams -r some_input_pcap -e "tcp dst port 6379" -o commands.csv`

Important, you can limit the number of open connections using
the -m switch. It defaults to keep the MRU 100K connections
open and will close the LRU connection. Progress our goal, never ending connections are not.

Happy parsing!
