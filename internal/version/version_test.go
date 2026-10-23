package version

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in          string
		maj, min, p int
		suffix      string
		vendor      bool
		wantErr     bool
	}{
		{"8.3.36", 8, 3, 36, "", false, false},
		{"8.1.2-1ubuntu2.14", 8, 1, 2, "-1ubuntu2.14", true, false},
		{"8.2.7+deb12u1", 8, 2, 7, "+deb12u1", true, false},
		{"8.5.0RC1", 8, 5, 0, "RC1", false, false},
		{"5.4.45", 5, 4, 45, "", false, false},
		{"8.3", 0, 0, 0, "", false, true},
		{"", 0, 0, 0, "", false, true},
		{"abc", 0, 0, 0, "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			v, err := Parse(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", v)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v.Major != tt.maj || v.Minor != tt.min || v.Patch != tt.p || v.Suffix != tt.suffix {
				t.Fatalf("got %+v", v)
			}
			if v.HasVendorSuffix() != tt.vendor {
				t.Fatalf("HasVendorSuffix=%v want %v", v.HasVendorSuffix(), tt.vendor)
			}
			if v.Raw != tt.in {
				t.Fatalf("Raw=%q", v.Raw)
			}
		})
	}
}

func TestParseBanner(t *testing.T) {
	tests := map[string]string{
		"PHP 8.3.6 (cli) (built: Oct 19 2026 15:16:58) (NTS)\nCopyright (c)": "8.3.6",
		"PHP 8.4.27 (fpm-fcgi) (built: Oct 21 2026)":                         "8.4.27",
		"PHP 8.1.2-1ubuntu2.14 (cgi-fcgi) (built: ...)":                      "8.1.2-1ubuntu2.14",
		"\r\nPHP 8.2.35 (cli) (ZTS Visual C++ 2019 x64)\r\n":                 "8.2.35",
	}
	for in, want := range tests {
		v, err := ParseBanner(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if v.String() != want {
			t.Fatalf("%q: got %s want %s", in, v, want)
		}
	}
	if _, err := ParseBanner("bash: php: command not found"); err == nil {
		t.Fatal("expected error for non-banner output")
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"8.3.36", "8.3.36", 0},
		{"8.3.35", "8.3.36", -1},
		{"8.3.37", "8.3.36", 1},
		{"8.4.0", "8.3.99", 1},
		{"9.0.0", "8.9.9", 1},
		{"8.5.12RC1", "8.5.12", -1},
		{"8.5.12", "8.5.12RC1", 1},
		{"8.3.36-1ubuntu1", "8.3.36", 0}, // vendor suffix does not change ordering
	}
	for _, tt := range tests {
		if got := MustParse(tt.a).Compare(MustParse(tt.b)); got != tt.want {
			t.Errorf("%s vs %s: got %d want %d", tt.a, tt.b, got, tt.want)
		}
	}
	if !MustParse("8.3.36").AtLeast(MustParse("8.3.36")) {
		t.Error("AtLeast should be inclusive")
	}
}

func TestMustParsePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	MustParse("nope")
}
