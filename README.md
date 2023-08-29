# go-btfs-api

> Go interface to BTFS HTTP API

## Install

```sh
go get -u github.com/simbadMarino/go-btfs-api
```

This will download the source into `$GOPATH/src/github.com/simbadMarino/go-btfs-api`.

## Usage

See [the godocs](https://pkg.go.dev/github.com/simbadMarino/go-btfs-api) for details on available methods.

### Example

Add a file with the contents "hello world!":

```go
package main

import (
	"fmt"
	"strings"
	"os"

	shell "github.com/simbadMarino/go-btfs-api"
)

func main() {
	// Where your local node is running on localhost:5001
	sh := shell.NewShell("localhost:5001")
	cid, err := sh.Add(strings.NewReader("hello world!"))
	if err != nil {
        fmt.Fprintf(os.Stderr, "error: %s", err)
        os.Exit(1)
	}
    fmt.Printf("added %s", cid)
}
```

For a more complete example, please see: https://github.com/simbadMarino/go-btfs-api/blob/master/tests/main.go

## Contribute

Contributions are welcome! Please check out the [issues](https://github.com/btfs/go-btfs-api/issues).

## License

MIT @ Bittorrent.
