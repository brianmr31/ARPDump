#!/bin/bash

while [ 1 ] ; do 
	#java -jar dist/ARPDump.jar -o arp-bootup.pcap
	#java -jar dist/ARPDump.jar -o arpSpoofAttackerSide.pcapng
	#java -jar dist/ARPDump.jar -o arpspoofData.pcapng
	#java -jar dist/ARPDump.jar -o NetcutARP.pcapng
	#java -jar dist/ARPDump.jar -o ArpSpoofServerSide.pcapng
	java -jar dist/ARPDump.jar -o testScan2.pcapng
	echo send
done
