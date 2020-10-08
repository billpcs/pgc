# pgc

### Generate pcap files from the command line!

It supports:
- vlans (vlan id, prio, dei)
- nested vlans
- raw data

Some examples:

```
./pgc                                      # untagged frame
./pgc -v 100                               # .1q 8100/100
./pgc -e 0x88a8 -v 100 -e 0x8100 -v 200    # QinQ 88a8/100/8100/200
./pgc -v1 -v2 -v3 -v4                      # 8100/1/8100/2/8100/3/8100/4
./pgc -r 810000640800                      # .1q 8100/100 with IP
./pgc -r 8100/0064/0800                    # ... same as above but nicer format
```


Quick start:

```sh
git clone --recurse-submodules https://github.com/billpcs/pgc
cd pgc
make linux # for linux
# or
make windows # for windows
```

