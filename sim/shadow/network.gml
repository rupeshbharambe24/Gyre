# Two regions with a slow link between them, so a route that crosses regions pays for it.
# Deliberately small: enough to exercise real TCP over non-trivial latency, not a model of
# the internet. Replace with a generated topology before drawing conclusions about scale.
graph [
  directed 0
  node [ id 0 label "region-a" host_bandwidth_down "100 Mbit" host_bandwidth_up "100 Mbit" ]
  node [ id 1 label "region-b" host_bandwidth_down "100 Mbit" host_bandwidth_up "100 Mbit" ]
  edge [ source 0 target 0 latency "15 ms" packet_loss 0.0 ]
  edge [ source 1 target 1 latency "15 ms" packet_loss 0.0 ]
  edge [ source 0 target 1 latency "70 ms" packet_loss 0.001 ]
]
