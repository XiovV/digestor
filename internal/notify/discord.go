package notify

import (
	"context"
	"errors"

	"github.com/XiovV/digestor/internal/config"
	"github.com/XiovV/digestor/internal/digest"
)

// Discord posts the digest to a channel webhook.
type Discord struct {
	cfg config.Discord
}

func (n *Discord) Name() string { return "discord" }

// TODO: split d.Markdown() into chunks of at most 2000 characters (Discord's
// message limit) and POST each as {"content": ...} to cfg.WebhookURL.
func (n *Discord) Send(ctx context.Context, d digest.Digest) error {
	return errors.New("not implemented")
}
