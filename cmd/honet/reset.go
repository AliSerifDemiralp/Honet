package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/auth"
	"github.com/AliSerifDemiralp/honet/internal/config"
	"github.com/AliSerifDemiralp/honet/internal/store"
)

// resetPassword sets a new admin password from the command line. readPw
// reads one password without echo.
func resetPassword(cfg config.Config, in io.Reader, out io.Writer, readPw func() (string, error)) error {
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()
	ctx := context.Background()
	a := auth.New(st, time.Now)
	user, err := a.Username(ctx)
	if errors.Is(err, auth.ErrNoUser) {
		return errors.New("No user yet; open the web UI to finish setup.")
	} else if err != nil {
		return err
	}
	fmt.Fprintf(out, "New password for %s: ", user)
	pw, err := readPw()
	fmt.Fprintln(out)
	if err != nil {
		return err
	}
	fmt.Fprint(out, "Repeat: ")
	again, err := readPw()
	fmt.Fprintln(out)
	if err != nil {
		return err
	}
	if pw != again {
		return errors.New("passwords do not match; nothing changed")
	}
	if err := a.ResetPassword(ctx, pw); err != nil {
		if errors.Is(err, auth.ErrWeakPassword) {
			return fmt.Errorf("password must be at least %d characters", auth.MinPasswordLen)
		}
		return err
	}
	fmt.Fprintln(out, "Password changed. Restart honet to sign out existing sessions: sudo systemctl restart honet")
	return nil
}
