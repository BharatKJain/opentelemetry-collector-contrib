# GELF log Exporter

<!-- status autogenerated section -->
| Status        |           |
| ------------- |-----------|
| Stability     | [alpha]: logs   |
| Distributions | [contrib] |
| [Code Owners](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/CONTRIBUTING.md#becoming-a-code-owner)    | [@BharatKJain](https://www.github.com/BharatKJain) |

[alpha]: https://github.com/open-telemetry/opentelemetry-collector#alpha
[contrib]: https://github.com/open-telemetry/opentelemetry-collector-releases/tree/main/distributions/otelcol-contrib
<!-- end autogenerated section -->

Sends GELF logs over UDP/TCP.

## Configuration Fields

| Field | Default | Description|
| --- | --- | --- |
| `endpoint`| 0.0.0.0:31250| A listen address of the form `<ip>:<port>`|
| `protocol` | udp | Supports tcp and udp |
| `compression` | gzip | Allowed values: gzip,zlib,none. |
| `send_chunks_with_overflow`                | false                  | Maximum chunks allowed is 128, if the number of chunks exceeds this limit, the message will be dropped. If set to true then |
| `chunk_size`          | 1420                | Default maximum chunk size is 1420 bytes. |
| `hostname`| "localhost"| hostname is the name of the host, which is added to the gelf message |
| `tcp_timeout_millis` | 2000 miliseconds | If TCP protocol is used then 2 seconds default timeout is used. Timeout must be less than 30000 milliseconds.


## Example Configuration

```yaml
exporters:
  gelfexporter:
    endpoint: "localhost:12201"
    protocol: udp
    compression: gzip
    send_chunks_with_overflow: true
    chunk_size: 1420
    hostname: "test-host"
```
