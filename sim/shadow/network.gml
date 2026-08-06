# Placeholder topology for Shadow. NOT a validated network model — two nodes with a
# symmetric link, enough to smoke-test a config and nothing more. Replace with a
# generated realistic topology before drawing any conclusion from a run.
graph [
  directed 0
  node [ id 0 label "region-a" host_bandwidth_down "100 Mbit" host_bandwidth_up "100 Mbit" ]
  node [ id 1 label "region-b" host_bandwidth_down "100 Mbit" host_bandwidth_up "100 Mbit" ]
  edge [ source 0 target 0 latency "20 ms" packet_loss 0.0 ]
  edge [ source 1 target 1 latency "20 ms" packet_loss 0.0 ]
  edge [ source 0 target 1 latency "60 ms" packet_loss 0.0 ]
]
