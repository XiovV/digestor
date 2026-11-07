package notify

import (
	"context"
	"errors"

	"github.com/XiovV/digestor/internal/config"
	"github.com/XiovV/digestor/internal/digest"
)

// Email sends the digest over SMTP.
type Email struct {
	cfg config.SMTP
}

func (e *Email) Name() string { return "email" }

// TODO: build an RFC 5322 message from d.Title() / d.Text() and send it with
// net/smtp (PlainAuth + STARTTLS on cfg.Port).
func (e *Email) Send(ctx context.Context, d digest.Digest) error {
	return errors.New("not implemented")
}
