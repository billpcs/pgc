#!/usr/bin/env bats

binary="../pgc"
pcapname="paibuild.pcap"
tcpdump="tcpdump -tqenr '$pcapname' 2>&1 | grep length"



@test "change vlan to 55" {
  $("$binary" -v 55)
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 666: vlan 55, p 0, ethertype IPv4, IP0 " 
  [ "$tcp" = "$wanted" ]
}

@test "change priority to 7" {
  $("$binary" -v 100 -p 7)
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 666: vlan 100, p 7, ethertype IPv4, IP0 " 
  [ "$tcp" = "$wanted" ]
}

@test "change priority to 5 and dei to 1" {
  $("$binary" -v 100 -p 5 -i 1)
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 666: vlan 100, p 5, DEI, ethertype IPv4, IP0 " 
  [ "$tcp" = "$wanted" ]
}

@test "change length to 1500" {
  $("$binary" -v 100 -l 1500) 
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 1500: vlan 100, p 0, ethertype IPv4, IP0 " 
  [ "$tcp" = "$wanted" ]
}

@test "change ethertype to 88a8" {
  $("$binary" -e 0x88a8) 
  tcp=$(eval "$tcpdump")
  wanted="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q-QinQ, length 666: vlan 100, p 0, ethertype IPv4, IP0 " 
  [ "$tcp" = "$wanted" ]
}


@test "vlans greater than 4095 wrap around" {
  
  $("$binary" -v 4096) 
  tcp1=$(eval "$tcpdump")
  wanted1="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 666: vlan 0, p 0, ethertype IPv4, IP0 " 

  $("$binary" -v 4097)
  tcp2=$(eval "$tcpdump")
  wanted2="08:00:27:2a:09:13 > 08:00:27:4c:27:11, 802.1Q, length 666: vlan 1, p 0, ethertype IPv4, IP0 " 

  [ "$tcp1" = "$wanted1" ]
  [ "$tcp2" = "$wanted2" ]
}





