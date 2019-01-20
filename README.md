# xrp
xdp \[reverse\] proxy,

4 modes for now:

| what?    | map   |  XDP_??? |
|--- |---|---|
| 1. TCP: simple tcp port change (JFF) |  (dport1) <--> (dport2) |  XDP_PASS | 
| 2. HTTP: port change ; multiple servers on a machine, advt one port | (URI, dport1) <--> (URI, dport2) | XDP_PASS |
| 3. TCP: port and address change ; ulta NAT |    (daddr1, dport1) <--> (daddr2, dport2) | XDP_TX |
| 4. HTTP: port and address change ; simple load balancer | (URI, daddr1, dport1) <--> (URI, daddr2, dport2) | XDP_TX |



setup:

1. install clang and llvm.
2. download your kernel from kernel.org and unzip into deps/kernelsrc
   by default kernel-4.15 (ubuntu 18.04) src is added.
   (will this cause Licensing issues? Dunno....)
3. make
4. edit xrp.config to set common options and add mappings
5. run xrp

Note:
1. poppulate cscope.files
```
find deps/kernelsrc/linux-4.15/include/* deps/kernelsrc/linux-4.15/arch/* deps/kernelsrc/linux-4.15/tools/* deps/kernelsrc/linux-4.15/kernel/bpf/* -name >> cscope.files
```

such fun! much wow!
