package transparency_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"codeberg.org/simplicer/trebaruna/src/transparency/domain"
	transparency "codeberg.org/simplicer/trebaruna/src/transparency/infrastructure"
)

func TestEveryRequestIsRecordedWithItsPurpose(t *testing.T) {
	transparency.Reset()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		_, _ = writer.Write([]byte("0123456789"))
	}))
	defer server.Close()

	client := transparency.Client(domain.PurposeTimestamp, 0)
	response, err := client.Post(server.URL+"/tsa?account=studio&secret=x", "application/timestamp-query", strings.NewReader("abcd"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()

	recorded := transparency.Connections()
	if len(recorded) != 1 {
		t.Fatalf("recorded %d connections, want 1", len(recorded))
	}
	connection := recorded[0]
	if connection.Purpose != domain.PurposeTimestamp || connection.Method != http.MethodPost || connection.Status != 200 {
		t.Errorf("connection = %+v", connection)
	}
	if connection.SentBytes != 4 || connection.Received != 10 {
		t.Errorf("bytes = %d sent, %d received; want 4 and 10", connection.SentBytes, connection.Received)
	}
	if strings.Contains(connection.URL, "studio") || strings.Contains(connection.URL, "secret=x") {
		t.Errorf("query values leaked into the record: %s", connection.URL)
	}
	if !strings.HasSuffix(connection.URL, "/tsa?account=%E2%80%A6&secret=%E2%80%A6") {
		t.Errorf("url = %s, want the path with redacted query keys", connection.URL)
	}
	if connection.Host() == "" {
		t.Error("the host must be readable for short listings")
	}
}

func TestAFailedConnectionIsRecordedToo(t *testing.T) {
	transparency.Reset()
	server := httptest.NewServer(http.NotFoundHandler())
	address := server.URL
	server.Close() // nothing listens any more

	if _, err := transparency.Client(domain.PurposeRevocation, 0).Get(address + "/ocsp"); err == nil {
		t.Fatal("a closed server must fail")
	}
	recorded := transparency.Connections()
	if len(recorded) != 1 || recorded[0].Error == "" || recorded[0].Purpose != domain.PurposeRevocation {
		t.Fatalf("recorded = %+v, want one failed revocation request", recorded)
	}
}

func TestCredentialsNeverReachTheRecord(t *testing.T) {
	transparency.Reset()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	address := strings.Replace(server.URL, "http://", "http://mario:segreto@", 1)
	response, err := transparency.Client(domain.PurposeTrustList, 0).Get(address + "/list.xml")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()

	if url := transparency.Connections()[0].URL; strings.Contains(url, "segreto") || strings.Contains(url, "mario") {
		t.Errorf("user information leaked: %s", url)
	}
}

func TestResetForgets(t *testing.T) {
	transparency.Reset()
	if len(transparency.Connections()) != 0 {
		t.Fatal("reset must leave an empty ledger")
	}
}

// TestALibraryConnectionIsRecordedAndClassified covers code we do not own:
// pdfsign builds its own http.Client for timestamps and revocation, which
// lands on the default transport that the slice wraps.
func TestALibraryConnectionIsRecordedAndClassified(t *testing.T) {
	transparency.Reset()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	libraryClient := &http.Client{} // what a third-party package does
	for _, request := range []struct {
		path, contentType string
		want              domain.Purpose
	}{
		{"/tsa", "application/timestamp-query", domain.PurposeTimestamp},
		{"/responder", "application/ocsp-request", domain.PurposeRevocation},
		{"/ca/latest.crl", "", domain.PurposeRevocation},
		{"/something", "text/plain", domain.PurposeUnattributed},
	} {
		response, err := libraryClient.Post(server.URL+request.path, request.contentType, strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()

		recorded := transparency.Connections()
		last := recorded[len(recorded)-1]
		if last.Purpose != request.want || last.Via != "library" {
			t.Errorf("%s: purpose %s via %q, want %s via library", request.path, last.Purpose, last.Via, request.want)
		}
	}
}

func TestOurOwnClientIsNotRecordedTwice(t *testing.T) {
	transparency.Reset()
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	response, err := transparency.Client(domain.PurposeTrustList, 0).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if recorded := transparency.Connections(); len(recorded) != 1 || recorded[0].Via != "" {
		t.Errorf("recorded = %+v, want exactly one entry from our client", recorded)
	}
}
