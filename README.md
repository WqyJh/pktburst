# pktburst

A DPDK-based program load and send pcap packets.

## Dependencies

Install dpdk first.

See [Compiling and Installing DPDK System-wide](https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html#compiling-and-installing-dpdk-system-wide).

## Build & Install

```bash
mkdir build/
cd build/
cmake ..
make
make install
```

## Run

Load `packets.pcap` and send packets through port 0.

```bash
sudo pktburst -l 0-1 -- --portmask 0x1 --pcap packets.pcap
```

You should see statistics like this. If there's only a few packets, the stats may be not correct, though no one will care about the stats of this situation. 

```bash
=== Packet burst statistics \ ===
-- PORT 0 --
	Built-in counters:
	TX Successful packets: 6253604
	TX Successful bytes: 4.55 GB (avg: 780 bytes/pkt)
	TX Unsuccessful packets: 0
Tx core 1 port 0
	packets=6253604	bytes=4879537051	drop=0
	Queue 0-3 TX: 6253604 pkts 4879537051 bytes
Tx core summary
	packets=6253604	bytes=4879537051	drop=0
	speed	152.65 Kpps	116.99 Mbps
===================================
```

You can adjust the arguments like the following.

- load pcap file packets.pcap
- 3 rx cores
- 16 tx queues each core (48 tx queues in total)
- 4096 tx_descs for each rx queue
- burst 1024 packets at a time
- 65536 mbufs in mbuf pool
- print statistics every 3000 ms
- repeat 10000 times

```bash
sudo pktburst -l 0-4 -- --portmask 0x1 --txq 16 --txd 4096 --burst 1024 --mbufs 65536 --cores 3 --stats 3000 --pcap packets.pcap --nbruns 10000
```

You should see the following statistics. There're stats for each tx core and summary for all tx cores.

```bash
=== Packet burst statistics | ===
-- PORT 0 --
	Built-in counters:
	TX Successful packets: 71603916
	TX Successful bytes: 5.40 GB (avg: 80 bytes/pkt)
	TX Unsuccessful packets: 0
Tx core 1 port 0
	packets=23932102	bytes=1938500262	drop=0
	Queue 0-15 TX: 23868893 pkts 1933380779 bytes
Tx core 2 port 0
	packets=23931368	bytes=1938440808	drop=0
	Queue 16-31 TX: 23867964 pkts 1933305976 bytes
Tx core 3 port 0
	packets=23931216	bytes=1938428496	drop=0
	Queue 32-47 TX: 23867540 pkts 1933270911 bytes
Tx core summary
	packets=71794686	bytes=5815369566	drop=0
	speed	11.35 Mpps	919.52 Mbps
===================================
```

```bash
sudo pktburst -l 0-1 -- --portmask 0x1 --pcap packets.pcap --bitrate 1000
```

Send packets at 1000 Mbps.

```bash
=== Packet burst statistics \ ===
-- PORT 1 --
        Built-in counters:
        TX Successful packets: 15748373
        TX Successful bytes: 991.241 M (avg: 65.00 bytes/pkt)
        TX Unsuccessful packets: 0
Tx core 1 port 1 queue 0-0
        packets=15748959        bytes=1039431294        error=0
Tx core summary
        packets=15748959        bytes=1039431294        error=0
        speed   1.786 Mpps      112.394 MBps    linerate=14.706 Mpps
===================================
```

```bash
sudo pktburst -l 0-1 -- --portmask 0x1 --pcap packets.pcap --pktrate 5000
```

Send packets at 5000 Kpps.

```bash
EAL: Detected 2 NUMA nodes
=== Packet burst statistics - ===
-- PORT 1 --
        Built-in counters:
        TX Successful packets: 18992464
        TX Successful bytes: 1.167 G (avg: 65.00 bytes/pkt)
        TX Unsuccessful packets: 0
Tx core 1 port 1 queue 0-0
        packets=18992651        bytes=1253514966        error=0
Tx core summary
        packets=18992651        bytes=1253514966        error=0
        speed   4.988 Mpps      313.966 MBps    linerate=14.706 Mpps
===================================
```
