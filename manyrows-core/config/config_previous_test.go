package config

import "testing"

func TestGetSessionAuthKeyPrevious(t *testing.T) {
	c := NewConfig("MANYROWS_")

	t.Run("unset means empty", func(t *testing.T) {
		t.Setenv("MANYROWS_SESSION_AUTH_KEY_PREVIOUS", "")
		got, err := c.GetSessionAuthKeyPrevious()
		if err != nil || len(got) != 0 {
			t.Fatalf("want empty, got %v err %v", got, err)
		}
	})

	t.Run("two values sliced to 64", func(t *testing.T) {
		a := make([]byte, 70)
		b := make([]byte, 64)
		for i := range a {
			a[i] = 'a'
		}
		for i := range b {
			b[i] = 'b'
		}
		t.Setenv("MANYROWS_SESSION_AUTH_KEY_PREVIOUS", string(a)+" , "+string(b))
		got, err := c.GetSessionAuthKeyPrevious()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || len(got[0]) != 64 || len(got[1]) != 64 {
			t.Fatalf("got %d entries: %v", len(got), got)
		}
		if got[0][0] != 'a' || got[1][0] != 'b' {
			t.Fatalf("order wrong")
		}
	})

	t.Run("too-short entry errors", func(t *testing.T) {
		t.Setenv("MANYROWS_SESSION_AUTH_KEY_PREVIOUS", "short")
		if _, err := c.GetSessionAuthKeyPrevious(); err == nil {
			t.Fatal("want error for short previous auth key")
		}
	})
}

func TestGetSessionSecretKeyPrevious(t *testing.T) {
	c := NewConfig("MANYROWS_")
	long := make([]byte, 40)
	for i := range long {
		long[i] = 'x'
	}
	t.Setenv("MANYROWS_SESSION_SECRET_KEY_PREVIOUS", string(long))
	got, err := c.GetSessionSecretKeyPrevious()
	if err != nil || len(got) != 1 || len(got[0]) != 32 {
		t.Fatalf("got %v err %v", got, err)
	}
	t.Setenv("MANYROWS_SESSION_SECRET_KEY_PREVIOUS", "short")
	if _, err := c.GetSessionSecretKeyPrevious(); err == nil {
		t.Fatal("want error for short previous secret key")
	}
}

func TestGetOTPPepperPrevious(t *testing.T) {
	c := NewConfig("MANYROWS_")
	t.Setenv("MANYROWS_OTP_PEPPER_PREVIOUS", " pepperA , pepperB ,, ")
	got, err := c.GetOTPPepperPrevious()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "pepperA" || got[1] != "pepperB" {
		t.Fatalf("got %v", got)
	}
}
