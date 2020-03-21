# pgc

```
$ ./pgc -h

Hello.                                                                                                                                                                                                                            
         __  ___  __                                                                                                                                                                                                              
        ((_)((_( ((_                                                                                                                                                                                                              
         ))   _))                                                                                                                                                                                                                 
                                                                                                                                                                                                                                  
pgc: Generate pcap files from the command line!                                                                                                                                                                                   
                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                  
(Default values in square brackets)

-f: Set the output file name          [paibuild.pcap]
-s: Set the source MAC                [08:00:27:2A:09:13]
-d: Set the destination MAC           [08:00:27:4C:27:11]
-e: Set the ethertype                 [0x8100]
-v: Set the VLAN ID                   [100]
-p: Set the VLAN Priority             [0]
-i: Set the DEI bit                   [0]
-l: The length of the frame in bytes  [666]
-h: This message


Mandatory examples:

Ethertype 0x88a8, vlan 222, priority 7, size 256
./pgc -e 0x88a8 -v 222 -p 7 -l 256 -f frame_88a8_222.pcap


Ethertype 0x8100, vlan 100, priority 0, size 40 with DEI set
./pgc -i 1 -l 40 -f frame_8100_100_dei.pcap


Report bugs to: me
```
