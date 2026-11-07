package notify

import (
	"context"
	"fmt"
	"io"

	"github.com/XiovV/digestor/internal/digest"
)

// Writer prints the digest, used for dry runs.
type Writer struct {
	W io.Writer
}

func (w *Writer) Name() string { return "stdout" }

func (w *Writer) Send(ctx context.Context, d digest.Digest) error {
	_, err := fmt.Fprint(w.W, d.Markdown())
	return err
}
