package feed

import (
	"context"
	"testing"
	"time"
)

func TestFetchNoURLs(t *testing.T) {
	items, err := Fetch(context.Background(), nil, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if len(items) != 0 {
		t.Errorf("Fetch() = %d items, want none", len(items))
	}
}
