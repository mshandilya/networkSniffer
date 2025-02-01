# Network Sniffer in C++

The following README file describes the instructions for reproducing the results for submission to the first assignment of CS 331. There is a single C++ source code file that needs to be run in order to start the sniffing process.

## Prerequisites
In order to send the packets over the network, we use the tool `tcpreplay`. As such, tcpreplay must be installed in your UNIX system prior to experimenting with our code. The installation in Linux distributions is quite simple.
```bash
sudo apt-get install net-tools
sudo apt-get install tcpreplay
```

## Initializing the Sniffer
In order to initialize the sniffer, first make an executable for the `sniffer.cpp` source code. Next, the sniffer should be run before sending over the packets through `tcpreplay`.
```bash
g++ sniffer.cpp -o sniffer
sudo ./sniffer
```

We can then run `tcpreplay` on our PCAP file
```bash
sudo tcpreplay -i eth0 --pps=50000 6.pcap
```

## Stopping the sniffer
To stop the sniffer, we use keyboard interrupts. While any of the packets received after the interrupt won't be processed, depending on when the interrupt occurs, the sniffer might wait for another packet (which won't be processed).
```bash
^C
```
