package shell

import (
	"context"
	"strings"
)

// Remove file by hash.
func (s *Shell) Remove(hash string) bool {
	var out map[string][]string
	rb := s.Request("rm", hash)
	if err := rb.Exec(context.Background(), &out); err != nil {
		return false
	}

	if out["Strings"] == nil {
		return false
	}

	for i := 0; i < len(out["Strings"]); i++ {
		if !strings.Contains(out["Strings"][i], "Removed") {
			return false
		}
	}

	return true
}
