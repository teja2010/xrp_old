# xrp
xdp \[reverse\] proxy,

4 modes for now:

| what?    | map   |  XDP_??? |
|--- |---|---|
| 1. TCP: simple tcp port change (JFF) |  (dport1) <--> (dport2) |  XDP_PASS | 
| 2. HTTP: port change ; multiple servers on a machine, advt one port | (URI, dport1) <--> (URI, dport2) | XDP_PASS |
| 3. TCP: port and address change ; ulta NAT |    (daddr1, dport1) <--> (daddr2, dport2) | XDP_TX |
| 4. HTTP: port and address change ; simple load balancer | (URI, daddr1, dport1) <--> (URI, daddr2, dport2) | XDP_TX |


such fun! much wow!
