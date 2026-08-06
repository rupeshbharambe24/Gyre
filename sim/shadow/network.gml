graph [
  directed 0
  node [
    id 0
    host_bandwidth_up "100 Mbit"
    host_bandwidth_down "100 Mbit"
  ]
  node [
    id 1
    host_bandwidth_up "100 Mbit"
    host_bandwidth_down "100 Mbit"
  ]
  edge [
    source 0
    target 0
    latency "15 ms"
    packet_loss 0.0
  ]
  edge [
    source 1
    target 1
    latency "15 ms"
    packet_loss 0.0
  ]
  edge [
    source 0
    target 1
    latency "70 ms"
    packet_loss 0.001
  ]
]
