package shell

import (
	"context"
	"testing"

	"github.com/cheekybits/is"
)

func TestLogger(t *testing.T) {
	is := is.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sh := NewShell(shellUrl)
	logger, err := sh.GetLogs(ctx)
	is.Nil(err)
	defer func() {
		err := logger.Close()
		is.Nil(err)
	}()
	l, err := logger.Next()
	is.Nil(err)
	is.NotNil(l)
}
