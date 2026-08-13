package corpus

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Tranco is the research-grade top-1M list: averaged over 30 days so a
// one-day spike cannot buy a ranking, combined from several upstream lists,
// and — the part that matters here — permanently archived under a list ID.
//
// A percentage is only defensible if the denominator is. Fetching
// /top-1m.csv.zip gives "whatever was served that Tuesday"; resolving the list
// ID first gives a frozen artifact anyone can re-download and re-run against.
//
// Worth stating plainly in any write-up: the top million is a biased sample.
// These are the domains most likely to have someone competent running DNS, so
// whatever www-support number comes out is closer to an upper bound than an
// average. If even this population has dropped www, the tail certainly has.
const trancoAPI = "https://tranco-list.eu/api/lists/date"

// TrancoList identifies one archived Tranco list.
type TrancoList struct {
	ListID    string    `json:"list_id"`
	Available bool      `json:"available"`
	Failed    bool      `json:"failed"`
	Download  string    `json:"download"`
	CreatedOn naiveTime `json:"created_on"`
}

// naiveTime parses Tranco's timestamps, which are ISO 8601 with no zone
// designator and so are rejected by time.Time's RFC 3339 unmarshaller.
type naiveTime struct{ time.Time }

func (t *naiveTime) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
		time.RFC3339,
		"2006-01-02",
	} {
		if parsed, err := time.Parse(layout, s); err == nil {
			t.Time = parsed
			return nil
		}
	}
	return fmt.Errorf("unrecognized tranco timestamp %q", s)
}

// FetchTrancoList resolves a date ("latest" or YYYY-MM-DD) to a list ID.
func FetchTrancoList(ctx context.Context, date string) (*TrancoList, error) {
	if date == "" {
		date = "latest"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, trancoAPI+"/"+date, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query tranco api: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tranco api returned %s for date %q", resp.Status, date)
	}
	var list TrancoList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("decode tranco api response: %w", err)
	}
	if list.Failed || !list.Available {
		return nil, fmt.Errorf("tranco list for %q is not available yet", date)
	}
	if list.Download == "" {
		list.Download = fmt.Sprintf("https://tranco-list.eu/download/%s/1000000", list.ListID)
	}
	return &list, nil
}

// FetchTranco downloads a Tranco list and freezes it to path with a manifest.
// limit caps the number of domains taken from the top of the ranking; 0 takes
// all of them.
func FetchTranco(ctx context.Context, path, date string, limit int) (*Manifest, error) {
	list, err := FetchTrancoList(ctx, date)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, list.Download, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download tranco list %s: %w", list.ListID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download tranco list %s: %s", list.ListID, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read tranco list %s: %w", list.ListID, err)
	}

	r, err := csvReader(body)
	if err != nil {
		return nil, err
	}

	domains, err := parseRanked(r, limit)
	if err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("tranco list %s parsed to zero domains", list.ListID)
	}

	m := Manifest{
		Source:    "tranco",
		SourceURL: list.Download,
		ListID:    list.ListID,
		Fetched:   time.Now().UTC(),
		Description: fmt.Sprintf(
			"Tranco daily list %s (created %s), rank order preserved, top %d",
			list.ListID, list.CreatedOn.Format("2006-01-02"), len(domains)),
	}
	stored, err := Write(path, domains, m)
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

// csvReader unwraps the payload, which is a zip in practice but is served as
// bare CSV from some endpoints.
func csvReader(body []byte) (io.Reader, error) {
	if len(body) >= 2 && body[0] == 'P' && body[1] == 'K' {
		zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			return nil, fmt.Errorf("open tranco zip: %w", err)
		}
		for _, f := range zr.File {
			if !strings.HasSuffix(f.Name, ".csv") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("open %s in tranco zip: %w", f.Name, err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("read %s in tranco zip: %w", f.Name, err)
			}
			return bytes.NewReader(data), nil
		}
		return nil, fmt.Errorf("no .csv inside tranco zip")
	}
	return bytes.NewReader(body), nil
}

// parseRanked reads "rank,domain" lines, keeping the file's order. Rank order
// is the natural freeze for Tranco and carries information sorting would
// throw away — it lets the results be sliced by popularity band later, which
// is where "do the top 1k behave differently from the bottom 100k" lives.
func parseRanked(r io.Reader, limit int) ([]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var domains []string
	seen := make(map[string]struct{})
	for sc.Scan() {
		d := normalize(sc.Text())
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		domains = append(domains, d)
		if limit > 0 && len(domains) >= limit {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse tranco csv: %w", err)
	}
	return domains, nil
}

// FromFile freezes an existing newline- or CSV-delimited list as a corpus.
func FromFile(src, dst string, limit int) (*Manifest, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	domains, err := parseRanked(f, limit)
	if err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("%s parsed to zero domains", src)
	}
	m := Manifest{
		Source:      "file",
		SourceURL:   src,
		Fetched:     time.Now().UTC(),
		Description: fmt.Sprintf("imported from %s", src),
	}
	stored, err := Write(dst, domains, m)
	if err != nil {
		return nil, err
	}
	return &stored, nil
}
