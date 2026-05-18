# Pulp-ext-udp

UDP networking capability for Pulp cells. Cells open sockets, send datagrams, and receive packets via the step event loop. Bounded per-socket ring buffer (drop-oldest, 1024 packets).

From [BananaLabs OSS](https://github.com/BananaLabs-OSS).

## Deployment

```go
import _ "github.com/BananaLabs-OSS/Pulp-ext-udp"
```

## Capability

- `network.udp` — `udp_listen`, `udp_send`, `udp_close` host imports
- Inbound packets surface as `udp.packet` StepEvents on the cell's step loop
