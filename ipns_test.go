package shell

import (
	"testing"
	"time"

	"github.com/cheekybits/is"
)

var examplesHashForIPNS = "/btfs/Qmbu7x6gJbsKDcseQv66pSbUcAA3Au6f7MfTYVXwvBxN2K"
var testKey = "self" // feel free to change to whatever key you have locally

func TestPublishDetailsWithKey(t *testing.T) {
	is := is.New(t)
	shell := NewShell(shellUrl)

	resp, err := shell.PublishWithDetails(examplesHashForIPNS, testKey, time.Second, time.Second, false)
	is.Nil(err)
	is.Equal(resp.Value, examplesHashForIPNS)
}

func TestPublishDetailsWithoutKey(t *testing.T) {
	is := is.New(t)
	shell := NewShell(shellUrl)

	resp, err := shell.PublishWithDetails(examplesHashForIPNS, "", time.Second, time.Second, false)
	is.Nil(err)
	is.Equal(resp.Value, examplesHashForIPNS)
}
