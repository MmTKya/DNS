// Command ed25519sign signs a file with the release key.
//
// It exists because the two signatures a release carries answer different
// questions. The cosign signature proves the release came from this project's
// CI, and a human verifies it before a manual download. This one is what the
// node itself checks before replacing its own binary, and it has to be
// verifiable by a static binary on a Raspberry Pi with no cosign, no network
// beyond the download, and no transparency log to consult.
//
// The key is read from the environment rather than a flag so it does not end
// up in a process listing or a CI log.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
)

const keyEnv = "RELEASE_SIGNING_KEY"

func main() {
	in := flag.String("in", "", "file to sign")
	out := flag.String("out", "", "where to write the signature")
	flag.Parse()

	if err := run(*in, *out); err != nil {
		fmt.Fprintln(os.Stderr, "ed25519sign:", err)
		os.Exit(1)
	}
}

func run(in, out string) error {
	if in == "" || out == "" {
		return fmt.Errorf("both -in and -out are required")
	}

	encoded := strings.TrimSpace(os.Getenv(keyEnv))
	if encoded == "" {
		return fmt.Errorf("%s is not set", keyEnv)
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decoding %s: %w", keyEnv, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		// Says the size without echoing the value.
		return fmt.Errorf("%s is %d bytes, want %d", keyEnv, len(raw), ed25519.PrivateKeySize)
	}

	body, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("reading %s: %w", in, err)
	}

	// Written 0600: on a shared runner the signature is public, but there is
	// no reason for anything else to be able to replace it before upload.
	if err = os.WriteFile(out, ed25519.Sign(ed25519.PrivateKey(raw), body), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", out, err)
	}

	return nil
}
