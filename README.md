# tcp-over-quic
`tcp-over-quic` is an WIP implementation for draft RFC [Tunneling TCP inside QUIC](https://datatracker.ietf.org/doc/draft-piraux-intarea-quic-tunnel-tcp/?include_text=1).

`client` accepts TCP connection from tcp clients and tunnels data through `quic` stream. `concentrator` accepts those quic streams and sends data towards remote TCP server.

**Note:** `tcp-over-quic` is not tested in production and probably not ready for production use. at this stage its just a project to learn `quic` and `rust`. 

<br><br>

## simple setup
* run `cargo build` to build project and generate binaries.

* start `concentrator` using `target/debug/concentrator --quic_serv_port=4433`. it will also generate self signed certificate required for quic tls. same certificate will be used by client as well.

* start `client`, client will listen on tcp port `6970` and it will connect to remote `quic` server `127.0.0.1:4433`. client will send addr `127.0.0.1:7970` as remote tcp address via `QUIC tunnel stream TLVs` for ALL its TCP connections.
```bash
target/debug/client \
    --tcp_source_port=6970 \
    --quic_serv_addr=127.0.0.1:4433 \
    --tcp_dest_addr=127.0.0.1:7970 \
    --quic_serv_cert_path=cert/public_cert.der \
    --quic_serv_name=localhost
```

* start tcp server on port `7971`. using `nc -l 127.0.0.1 7970`

* send data via tcp client on port `6970` using `echo "From tcp client" | nc 127.0.0.1 6970`
