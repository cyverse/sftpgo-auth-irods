package auth

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
)

// chunkedReader hands out data in fixed size chunks and then reports EOF, the
// way ReadDataObject does.
func chunkedReader(data []byte, chunk int, eofWithData bool) func([]byte) (int, error) {
	offset := 0
	return func(buffer []byte) (int, error) {
		if offset >= len(data) {
			return 0, io.EOF
		}

		size := min(chunk, min(len(buffer), len(data)-offset))
		copy(buffer, data[offset:offset+size])
		offset += size

		if eofWithData && offset >= len(data) {
			// EOF reported together with the last chunk
			return size, io.EOF
		}
		return size, nil
	}
}

// TestReadAllLimited covers the size bound that keeps the auth hook from
// buffering an authorized_keys object of any size. Over the limit the prefix is
// kept rather than the read failing, so the keys that did fit are still checked.
func TestReadAllLimited(t *testing.T) {
	tests := []struct {
		name          string
		size          int
		chunk         int
		limit         int64
		eofWithData   bool
		wantTruncated bool
	}{
		{name: "empty", size: 0, chunk: 1024, limit: 1024},
		{name: "well under the limit", size: 100, chunk: 1024, limit: 1024},
		{name: "exactly at the limit", size: 1024, chunk: 1024, limit: 1024},
		{name: "one byte over the limit", size: 1025, chunk: 1024, limit: 1024, wantTruncated: true},
		{name: "far over the limit", size: 1 << 20, chunk: 64 * 1024, limit: 1024, wantTruncated: true},
		{
			name:  "spread over many chunks",
			size:  200 * 1024,
			chunk: 4 * 1024,
			limit: 1 << 20,
		},
		{
			name:          "the limit is crossed partway through",
			size:          200 * 1024,
			chunk:         4 * 1024,
			limit:         100 * 1024,
			wantTruncated: true,
		},
		{
			name:        "EOF reported with the last chunk",
			size:        5000,
			chunk:       1024,
			limit:       1 << 20,
			eofWithData: true,
		},
		{
			name:          "EOF with the last chunk, over the limit",
			size:          5000,
			chunk:         1024,
			limit:         4096,
			eofWithData:   true,
			wantTruncated: true,
		},
		{
			// the limit lands inside a chunk, so the prefix has to be cut to it
			name:          "limit falls inside a chunk",
			size:          10000,
			chunk:         4096,
			limit:         5000,
			wantTruncated: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := bytes.Repeat([]byte("k"), test.size)

			got, truncated, err := readAllLimited(chunkedReader(data, test.chunk, test.eofWithData), test.limit)
			if err != nil {
				t.Fatalf("readAllLimited() failed: %v", err)
			}

			if truncated != test.wantTruncated {
				t.Errorf("truncated = %v, want %v", truncated, test.wantTruncated)
			}

			want := data
			if test.wantTruncated {
				want = data[:test.limit]
			}
			if !bytes.Equal(got, want) {
				t.Errorf("read %d bytes, want %d", len(got), len(want))
			}
			if int64(len(got)) > test.limit {
				t.Errorf("read %d bytes, which is past the limit of %d", len(got), test.limit)
			}
		})
	}
}

// TestReadAllLimitedStopsReadingAtTheLimit is the point of the limit: a large
// object must not be pulled over the wire and held in memory in full. Checking
// only the returned prefix would pass even if everything had been read.
func TestReadAllLimitedStopsReadingAtTheLimit(t *testing.T) {
	const (
		objectSize = 64 << 20 // far larger than any authorized_keys
		chunk      = 64 * 1024
	)
	limit := int64(1024 * 1024)

	// hand out data without allocating the object, counting what was asked for
	handedOut := int64(0)
	read := func(buffer []byte) (int, error) {
		if handedOut >= objectSize {
			return 0, io.EOF
		}

		size := min(len(buffer), chunk)
		for i := range size {
			buffer[i] = 'k'
		}
		handedOut += int64(size)
		return size, nil
	}

	got, truncated, err := readAllLimited(read, limit)
	if err != nil {
		t.Fatalf("readAllLimited() failed: %v", err)
	}
	if !truncated {
		t.Error("truncated = false, want the object to be reported as cut")
	}
	if int64(len(got)) != limit {
		t.Errorf("returned %d bytes, want the %d byte prefix", len(got), limit)
	}

	// one extra read round past the limit is expected, nothing beyond that
	if maxHandedOut := limit + chunk; handedOut > maxHandedOut {
		t.Errorf("read %d bytes from a %d byte object, want at most %d",
			handedOut, int64(objectSize), maxHandedOut)
	}
}

// TestReadAllLimitedKeepsUsableKeys checks that a key inside the prefix is
// still found when the object is cut, and that a key past the cut is not.
func TestReadAllLimitedKeepsUsableKeys(t *testing.T) {
	// keyA near the front, keyB past the limit
	var authorizedKeys bytes.Buffer
	authorizedKeys.WriteString(keyA + "\n")
	authorizedKeys.WriteString("# ")
	authorizedKeys.WriteString(strings.Repeat("x", 4096))
	authorizedKeys.WriteString("\n")
	authorizedKeys.WriteString(keyB + "\n")

	limit := int64(2048)
	got, truncated, err := readAllLimited(chunkedReader(authorizedKeys.Bytes(), 512, false), limit)
	if err != nil {
		t.Fatalf("readAllLimited() failed: %v", err)
	}
	if !truncated {
		t.Fatal("truncated = false, want the object to be reported as cut")
	}

	foundA, _, err := checkAuthorizedKey(got, mustParseKey(t, keyA))
	if err != nil {
		t.Fatalf("checkAuthorizedKey() failed for the key inside the prefix: %v", err)
	}
	if !foundA {
		t.Error("the key inside the prefix was not found")
	}

	foundB, _, err := checkAuthorizedKey(got, mustParseKey(t, keyB))
	if err != nil {
		t.Fatalf("checkAuthorizedKey() failed for the key past the cut: %v", err)
	}
	if foundB {
		t.Error("a key past the cut was found, which the prefix cannot contain")
	}
}

// TestReadAllLimitedCutLineIsSkipped checks that cutting a key line in half
// does not break parsing of the rest.
func TestReadAllLimitedCutLineIsSkipped(t *testing.T) {
	var authorizedKeys bytes.Buffer
	authorizedKeys.WriteString(keyA + "\n")
	authorizedKeys.WriteString(keyB + "\n")

	// land the limit in the middle of the keyB line
	limit := int64(len(keyA) + 1 + len(keyB)/2)

	got, truncated, err := readAllLimited(chunkedReader(authorizedKeys.Bytes(), 64, false), limit)
	if err != nil {
		t.Fatalf("readAllLimited() failed: %v", err)
	}
	if !truncated {
		t.Fatal("truncated = false, want the object to be reported as cut")
	}

	foundA, _, err := checkAuthorizedKey(got, mustParseKey(t, keyA))
	if err != nil {
		t.Fatalf("checkAuthorizedKey() failed: %v", err)
	}
	if !foundA {
		t.Error("the whole key before the cut line was not found")
	}

	foundB, _, err := checkAuthorizedKey(got, mustParseKey(t, keyB))
	if err != nil {
		t.Fatalf("checkAuthorizedKey() failed on the cut line: %v", err)
	}
	if foundB {
		t.Error("the half of a key line matched a key")
	}
}

// TestReadAllLimitedPropagatesAReadError checks that a failing read is reported
// rather than treated as the end of the object.
func TestReadAllLimitedPropagatesAReadError(t *testing.T) {
	wantErr := "connection reset"
	calls := 0
	read := func(buffer []byte) (int, error) {
		calls++
		if calls == 1 {
			copy(buffer, "ssh-ed25519 AAAA")
			return 16, nil
		}
		return 0, errors.New(wantErr)
	}

	got, _, err := readAllLimited(read, 1<<20)
	if err == nil {
		t.Fatalf("readAllLimited() read %q, want an error", got)
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("error = %v, want it to contain %q", err, wantErr)
	}
	if got != nil {
		t.Errorf("read %q, want nothing on failure", got)
	}
}

// TestReadAllLimitedStopsWithoutProgress checks that a read returning no data
// and no EOF ends with an error instead of spinning forever or returning a
// truncated file, which would look like a shorter authorized_keys.
func TestReadAllLimitedStopsWithoutProgress(t *testing.T) {
	calls := 0
	read := func(buffer []byte) (int, error) {
		calls++
		if calls == 1 {
			copy(buffer, "ssh-ed25519 AAAA")
			return 16, nil
		}
		// never reports EOF and never hands out data
		return 0, nil
	}

	got, _, err := readAllLimited(read, 1<<20)
	if err == nil {
		t.Fatalf("readAllLimited() read %q, want an error", got)
	}
	if !strings.Contains(err.Error(), "no data") {
		t.Errorf("error = %v, want it to mention that no data arrived", err)
	}
	if calls > 3 {
		t.Errorf("read was called %d times, want it to stop as soon as it stopped making progress", calls)
	}
}

// TestMaxAuthorizedKeysSizeHoldsManyKeys checks that the limit is generous
// enough that no realistic authorized_keys is refused.
func TestMaxAuthorizedKeysSizeHoldsManyKeys(t *testing.T) {
	line := keyRSA + "\n"

	if keys := maxAuthorizedKeysSize / int64(len(line)); keys < 1000 {
		t.Errorf("the limit holds only %d RSA keys, want at least 1000", keys)
	}
}
