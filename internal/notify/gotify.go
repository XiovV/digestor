package notify

import (
	"context"
	"errors"

	"github.com/XiovV/digestor/internal/config"
	"github.com/XiovV/digestor/internal/digest"
)

// Gotify pushes the digest to a Gotify server.
type Gotify struct {
	cfg config.Gotify
}

func (g *Gotify) Name() string { return "gotify" }

// TODO: POST {"title", "message", "priority", "extras": {"client::display":
// {"contentType": "text/markdown"}}} to cfg.URL + "/message" with the
// X-Gotify-Key header set to cfg.Token.
func (g *Gotify) Send(ctx context.Context, d digest.Digest) error {
	return errors.New("not implemented")
}
