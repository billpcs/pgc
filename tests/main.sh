#!/usr/bin/env bats

binary="../pgc"
pcapname="paibuild.pcap"
tcpdump="tcpdump -tqenr '$pcapname' 2>&1 | grep length"

@test "untagged frame" {
  "$binary" -l 200
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, IPv4, length 200: IP0 "
  [ "$tcp" = "$wanted" ]	
}

@test "change vlan to 55" {
  "$binary" -v 55
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 666: vlan 55, p 0, ethertype IPv4, IP0 " 
  [ "$tcp" = "$wanted" ]
}

@test "change priority to 7" {
  "$binary" -v 100 -p 7
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 666: vlan 100, p 7, ethertype IPv4, IP0 " 
  [ "$tcp" = "$wanted" ]
}

@test "change priority to 5 and dei to 1" {
  "$binary" -v 100 -p 5 -i 1
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 666: vlan 100, p 5, DEI, ethertype IPv4, IP0 " 
  [ "$tcp" = "$wanted" ]
}

@test "change length to 1500" {
  "$binary" -v 100 -l 1500
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 1500: vlan 100, p 0, ethertype IPv4, IP0 " 
  [ "$tcp" = "$wanted" ]
}

@test "change ethertype to 88a8" {
  "$binary" -e 0x88a8
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q-QinQ, length 666: vlan 100, p 0, ethertype IPv4, IP0 " 
  [ "$tcp" = "$wanted" ]
}

@test "test two vlans" {
  "$binary" -e 0x88a8 -v 10 -e 8100 -v 20 -l 300
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q-QinQ, length 300: vlan 10, p 0, ethertype 802.1Q, vlan 20, p 0, ethertype IPv4, IP0 "
  [ "$tcp" = "$wanted" ]
}

@test "test many vlans 1" {
  "$binary" -e 0x88a8 -v10 -v20 -v30 -p1 -p2
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q-QinQ, length 666: vlan 10, p 0, ethertype 802.1Q, vlan 20, p 0, ethertype 802.1Q, vlan 30, p 1, ethertype 802.1Q, vlan 100, p 2, ethertype IPv4, IP0 "
  [ "$tcp" = "$wanted" ]
}

@test "test many vlans 2" {
  "$binary" -v10 -v20 -v30 -v40 -v50 -l 120
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 120: vlan 10, p 0, ethertype 802.1Q, vlan 20, p 0, ethertype 802.1Q, vlan 30, p 0, ethertype 802.1Q, vlan 40, p 0, ethertype 802.1Q, vlan 50, p 0, ethertype IPv4, IP0 "
  [ "$tcp" = "$wanted" ]
}

@test "vlans greater than 4095 wrap around" {
  
  "$binary" -v 4096
  tcp1=$(eval "$tcpdump")
  wanted1="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 666: vlan 0, p 0, ethertype IPv4, IP0 " 

  "$binary" -v 4097
  tcp2=$(eval "$tcpdump")
  wanted2="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 666: vlan 1, p 0, ethertype IPv4, IP0 " 

  [ "$tcp1" = "$wanted1" ]
  [ "$tcp2" = "$wanted2" ]
}

@test "raw data, ip only" {
  "$binary" -r 080045000014
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, IPv4, length 666: 0.0.0.0 > 0.0.0.0:  ip-proto-0 0"
  echo "$tcp"
  echo "$wanted"
  [ "$tcp" = "$wanted" ]
}

@test "raw data, vlan + ip 1" {
  "$binary" -v 100 -e 0x8100 -r 0800 -l 50
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 50: vlan 100, p 0, ethertype IPv4, IP0 "
  echo "$tcp"
  echo "$wanted"
  [ "$tcp" = "$wanted" ]
}

@test "raw data, vlan + ip 2" {
  "$binary"  -r 810000640800 -l 50
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 50: vlan 100, p 0, ethertype IPv4, IP0 "
  echo "$tcp"
  echo "$wanted"
  [ "$tcp" = "$wanted" ]
}

@test "raw data, STP frame" {
  "$binary" -d "01:80:c2:00:00:00" -r "0079424203000003027c8000000c305dd100000000008000000c305dd10080050000140002000f00000050000000000000000000000000000000000000000000000000000000000000000000000055bf4e8a44b25d442868549c1bf7720f00030d408000001aa197d180137c8005000c305dd10000030d40808013" -l135
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 01:80:c2:00:00:00, 802.3, length 121: LLC, dsap STP (0x42) Individual, ssap STP (0x42) Command, ctrl 0x03: STP 802.1s, Rapid STP, CIST Flags [Learn, Forward, Agreement], length 118"
  echo "$tcp"
  echo "$wanted"
  [ "$tcp" = "$wanted" ]
}


@test "filename simple" {
  "$binary"  -f "test.pcap"
  [ -f "test.pcap" ]
}

@test "filename long" {
  # make a filename that must be tructuated
  filename=$(printf 'e%.0s' {1..200})
  # this must be the result of the tructuated file
  realfilename=$(echo "$filename" | cut -c1-50)
  "$binary"  -f "$filename"
  [ -f "$realfilename" ]
}




