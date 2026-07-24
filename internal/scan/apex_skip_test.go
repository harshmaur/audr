package scan

import "testing"

func TestShouldSkipFileAllowsExactApexStagingArchive(t *testing.T) {
	if shouldSkipFile("/tmp/osalogging.zip") {
		t.Fatal("exact Apex campaign staging archive must reach format detection")
	}
	if !shouldSkipFile("/repo/docs/osalogging.zip") {
		t.Fatal("unrelated zip archives must remain skipped")
	}
}
