package main

import "testing"

func TestValidateListenAddress(t *testing.T) {
	t.Setenv("OAUTHSONAS_ALLOW_NON_LOOPBACK", "")
	for _, address := range []string{"127.0.0.1:8181", "[::1]:8181", "localhost:8181"} {
		if err := validateListenAddress(address); err != nil {
			t.Errorf("validateListenAddress(%q) returned %v", address, err)
		}
	}
	if err := validateListenAddress("0.0.0.0:8181"); err == nil {
		t.Fatal("non-loopback address was accepted")
	}
}

func TestValidateListenAddressAllowsExplicitOverride(t *testing.T) {
	t.Setenv("OAUTHSONAS_ALLOW_NON_LOOPBACK", "true")
	if err := validateListenAddress("0.0.0.0:8181"); err != nil {
		t.Fatalf("explicit override was rejected: %v", err)
	}
}
