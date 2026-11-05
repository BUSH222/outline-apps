// Copyright 2026 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keys

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"localhost/client/go/outline/macoscli/internal/redact"
)

// DefaultFetchTimeout matches the app's FetchResource timeout.
const DefaultFetchTimeout = 10 * time.Second

const maxRedirects = 10

// Fetcher downloads dynamic key configs. It mirrors the app's FetchResource
// (an HTTP GET, a 10 s timeout, and an error on non-2xx status), but never puts
// the URL's path or query in errors and refuses redirects away from https.
type Fetcher struct {
	// Transport is the HTTP transport. nil means http.DefaultTransport.
	Transport http.RoundTripper
	// Timeout bounds the whole request. Zero means DefaultFetchTimeout.
	Timeout time.Duration
}

// Fetch returns the response body of an https GET to u.
func (f *Fetcher) Fetch(ctx context.Context, u *url.URL) (string, error) {
	display := redact.URL(u.String())
	if u.Scheme != "https" {
		return "", fmt.Errorf("refusing to fetch %s: only https is allowed", display)
	}
	timeout := f.Timeout
	if timeout == 0 {
		timeout = DefaultFetchTimeout
	}
	client := &http.Client{
		Transport: f.Transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to %s: only https is allowed", req.URL.Scheme)
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("fetching %s: invalid request", display)
	}
	resp, err := client.Do(req)
	if err != nil {
		// *url.Error embeds the full URL in its message; keep only the cause.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return "", fmt.Errorf("fetching %s: %w", display, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("fetching %s: server returned %s", display, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInputSize+1))
	if err != nil {
		return "", fmt.Errorf("fetching %s: reading body: %w", display, err)
	}
	if len(body) > maxInputSize {
		return "", fmt.Errorf("fetching %s: config is larger than 1 MiB", display)
	}
	return string(body), nil
}
