# hyper-large-payload
Repro code sample for demo-ing  hyper slowdown with large payloads of around 16 MB. There seems to be a 2x speedup when
the client sends data in frames rather than a full payload.

## Usage

## Certificate generation
Assuming that you have `openssl` installed, running the following command
```
./scripts/local_certs.sh
```
should result in the creation of
- repro-ca-cert.pem
- server-cert.pem
- server-key.pem
- server-ext.cnf

These files will be used by the client and the server

## Timing results
The key difference is between the using frames or not when using large buffers on the server side. The difference does 
not change dependent on the use of http or https.
```
bash-3.2$ time ./target/release/transporter  --use-tls  --use-large-buffers combined

real	0m19.012s
user	0m18.936s
sys	0m0.698s
```
versus
```
bash-3.2$ time ./target/release/transporter  --use-tls  --use-large-buffers --use-frames combined
Error serving connection: connection error

real	0m10.117s
user	0m9.949s
sys	0m0.468s
```