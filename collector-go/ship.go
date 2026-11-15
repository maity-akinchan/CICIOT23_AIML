package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type stopShippingError struct {
	msg string
}

func (e *stopShippingError) Error() string { return e.msg }

type shipper struct {
	apiURL      string
	authToken   string
	collectorID string
	captureMode string
	session     string
	linkName    string
	cfg         Config
	stats       *Stats
	client      *http.Client
	maxBatch    int
	flushEvery  time.Duration
	loggedFirst bool
}

func newShipper(cfg Config, session, linkName string, stats *Stats) *shipper {
	return &shipper{
		apiURL:      cfg.APIURL,
		authToken:   cfg.AuthToken,
		collectorID: cfg.CollectorID,
		captureMode: cfg.captureMode(),
		session:     session,
		linkName:    linkName,
		cfg:         cfg,
		stats:       stats,
		client:      &http.Client{Timeout: 5 * time.Second},
		maxBatch:    maxBatchWindows,
		flushEvery:  200 * time.Millisecond,
	}
}

func (s *shipper) loop(in <-chan Window) error {
	ticker := time.NewTicker(s.flushEvery)
	defer ticker.Stop()
	batch := make([]Window, 0, s.maxBatch)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		sending := batch
		batch = make([]Window, 0, s.maxBatch)
		if err := s.post(sending); err != nil {
			return err
		}
		return nil
	}
	for {
		select {
		case window, ok := <-in:
			if !ok {
				return flush()
			}
			batch = append(batch, window)
			if len(batch) >= s.maxBatch {
				if err := flush(); err != nil {
					if _, stop := err.(*stopShippingError); stop {
						return err
					}
					log.Printf("ingest batch failed: %v", err)
				}
			}
		case <-ticker.C:
			if err := flush(); err != nil {
				if _, stop := err.(*stopShippingError); stop {
					return err
				}
				log.Printf("ingest batch failed: %v", err)
			}
		}
	}
}

func (s *shipper) post(batch []Window) error {
	body, err := encodeBatch(s.cfg, s.collectorID, s.captureMode, s.session, s.linkName, s.stats, batch)
	if err != nil {
		s.stats.HTTPFailures.Add(1)
		return err
	}
	return s.send(body, len(batch))
}

func encodeBatch(cfg Config, collectorID, captureMode, session, linkName string, stats *Stats, batch []Window) ([]byte, error) {
	payload := ingestRequest{
		CollectorID: collectorID,
		CaptureMode: captureMode,
		SourceRef:   cfg.sourceRef(session, linkName, stats),
		Windows:     batch,
	}
	return jsonMarshal(payload)
}

func (s *shipper) send(body []byte, windows int) error {
	var last error
	for attempt := 1; attempt <= httpAttempts; attempt++ {
		if attempt > 1 {
			time.Sleep(time.Duration(attempt-1) * 200 * time.Millisecond)
		}
		req, err := http.NewRequest(http.MethodPost, s.apiURL, bytes.NewReader(body))
		if err != nil {
			s.stats.HTTPFailures.Add(1)
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "ciciot23-sentinel-collector/"+extractorVersion)
		if s.authToken != "" {
			req.Header.Set("Authorization", "Bearer "+s.authToken)
		}
		resp, err := s.client.Do(req)
		if err != nil {
			last = err
			log.Printf("ingest attempt %d/%d: %v", attempt, httpAttempts, err)
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			s.stats.HTTPSuccess.Add(1)
			if !s.loggedFirst {
				s.loggedFirst = true
				log.Printf("ingest accepted first batch (%d windows) capture_mode=%s contract=%s", windows, s.captureMode, contractID)
			}
			return nil
		}
		last = fmt.Errorf("status %d: %s", resp.StatusCode, bytes.TrimSpace(respBody))
		log.Printf("ingest attempt %d/%d: %v", attempt, httpAttempts, last)
		if permanentStatus(resp.StatusCode) {
			s.stats.HTTPFailures.Add(1)
			return &stopShippingError{msg: "backend rejected collector payload: " + last.Error()}
		}
	}
	s.stats.HTTPFailures.Add(1)
	return fmt.Errorf("ingest failed after %d attempts: %w", httpAttempts, last)
}

func permanentStatus(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

// probeHealth confirms the legacy backend is reachable. The current /health
// payload does not advertise a feature contract. If a future response includes
// allowed_contracts or allowed_input_modes, a mismatch stops shipping instead
// of falling back to another model.
func probeHealth(ctx context.Context, cfg Config) error {
	health, err := cfg.healthURL()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	var last error
	for {
		err := checkHealth(ctx, health, cfg)
		if err == nil {
			return nil
		}
		var stop *stopShippingError
		if ok := asStop(err, &stop); ok {
			return err
		}
		last = err
		if time.Now().After(deadline) {
			return fmt.Errorf("backend health check failed: %w", last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func asStop(err error, target **stopShippingError) bool {
	stop, ok := err.(*stopShippingError)
	if !ok {
		return false
	}
	*target = stop
	return true
}

func checkHealth(ctx context.Context, health string, cfg Config) error {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, health, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ciciot23-sentinel-collector/"+extractorVersion)
	if cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.AuthToken)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s status %d", health, resp.StatusCode)
	}
	doc, err := jsonObject(body)
	if err != nil {
		log.Printf("backend /health is not a JSON object; continuing with contract %s", contractID)
	} else {
		if err := contractsCompatible(doc, cfg.captureMode()); err != nil {
			return err
		}
		if bootstrap, ok := doc["is_bootstrap_model"].(bool); ok && bootstrap {
			log.Printf("warning: backend reports a bootstrap model; collector contract remains %s", contractID)
		}
	}
	log.Printf("backend health ok; shipping %s base features only (extractor %s, source_type=%s, capture_mode=%s). Legacy /health does not select a model.", contractID, extractorVersion, cfg.sourceType(), cfg.captureMode())
	return nil
}

func contractsCompatible(doc map[string]any, captureMode string) error {
	if raw, ok := doc["allowed_contracts"]; ok {
		if !jsonListContains(raw, contractID) {
			return &stopShippingError{msg: "backend allowed_contracts does not include " + contractID}
		}
	}
	if raw, ok := doc["allowed_input_modes"]; ok {
		if !jsonListContains(raw, captureMode) {
			return &stopShippingError{msg: "backend allowed_input_modes does not include " + captureMode}
		}
	}
	return nil
}

func jsonListContains(raw any, want string) bool {
	list, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if text, ok := item.(string); ok && text == want {
			return true
		}
	}
	return false
}
