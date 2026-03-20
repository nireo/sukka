# sukka

`sukka` is a tiny SOCKS5 proxy server written in Go.

It supports:

- no-auth SOCKS5 negotiation
- `CONNECT` requests
- IPv4, IPv6, and domain targets
- configurable server address, logger, and dial function

Example:

```go
package main

import (
	"log"

	"github.com/nireo/sukka"
)

func main() {
	s := &sukka.Server{Addr: ":1080"}
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
```

With that server running on `127.0.0.1:1080`, you can send traffic through it with curl:

```sh
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```
