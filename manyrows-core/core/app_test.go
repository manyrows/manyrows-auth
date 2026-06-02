package core

import (
	"testing"
	"time"
)

func TestApp_SessionTTL_Default(t *testing.T) {
	app := &App{SessionTTLMinutes: nil}
	got := app.SessionTTL()
	if got != 0 {
		t.Errorf("expected 0 for nil SessionTTLMinutes, got %v", got)
	}
}

func TestApp_SessionTTL_Custom(t *testing.T) {
	minutes := 30
	app := &App{SessionTTLMinutes: &minutes}
	got := app.SessionTTL()
	want := 30 * time.Minute
	if got != want {
		t.Errorf("expected %v, got %v", want, got)
	}
}

func TestApp_SessionTTL_Zero(t *testing.T) {
	zero := 0
	app := &App{SessionTTLMinutes: &zero}
	got := app.SessionTTL()
	if got != 0 {
		t.Errorf("expected 0 for SessionTTLMinutes=0, got %v", got)
	}
}
