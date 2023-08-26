package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractVideoUrl(t *testing.T) {

	assert.Equal(t, "www.youtube.com/watch?v=Mwh3uILEO5I",
		ExtractVideoUrl("  www.youtube.com/watch?v=Mwh3uILEO5I"))

	assert.Equal(t, "https://www.youtube.com/watch?v=Mwh3uILEO5I",
		ExtractVideoUrl("https://www.youtube.com/watch?v=Mwh3uILEO5I&list=PLkvwWA9vMwPKHh9-oNdKh2v8hlZjxE1-L&index=42&pp=gAQBiAQB"))
}
