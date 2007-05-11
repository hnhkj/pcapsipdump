pcapsipdump version 0.1.3

Usage: pcapsipdump [-fp] [-i <interface>] [-r <file>] [-d <working directory>]
 -f     Do not fork or detach from controlling terminal.
 -p     Do not put the interface into promiscuous mode.

pcapsipdump is a tool for dumping SIP sessions (+RTP
traffic, if available) to disk in a fashion similar
to "tcpdump -w" (format is exactly the same), but one
file per sip session (even if there is thousands of
concurrent SIP sessions).

pcapsipdump can also be used to split "bulk" pcap file
into bunch of individual files (one per call):
pcapsipdump -r <bulkfile> -d <dir-for-bunch-of-files>

for Red Hat/CentOS/Fedora rpm instructions see redhat/ dir
