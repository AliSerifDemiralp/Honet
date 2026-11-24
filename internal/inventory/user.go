package inventory

import (
	"context"

	"github.com/AliSerifDemiralp/honet/internal/classify"
	"github.com/AliSerifDemiralp/honet/internal/netutil"
)

func (inv *Inventory) execOne(ctx context.Context, q string, args ...any) error {
	res, err := inv.st.DB.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Identify stores the user's name, notes, type override and "known" flag.
func (inv *Inventory) Identify(ctx context.Context, id int64, name, notes, manualType string, known bool) error {
	if manualType != "" && !classify.IsType(manualType) {
		return ErrBadType
	}
	return inv.execOne(ctx, `UPDATE devices SET name = ?, notes = ?, manual_type = ?, known = ? WHERE id = ?`,
		netutil.CleanText(name, 64), netutil.CleanText(notes, 500), manualType, known, id)
}
