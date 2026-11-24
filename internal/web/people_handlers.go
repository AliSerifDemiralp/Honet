package web

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"

	"github.com/AliSerifDemiralp/honet/internal/inventory"
)

const presenceDays = 7

func (s *server) peopleRoutes() {
	s.mux.HandleFunc("GET /people", s.peoplePage)
	s.mux.HandleFunc("POST /people", s.personAdd)
	s.mux.HandleFunc("POST /people/{id}/link", s.personLink)
	s.mux.HandleFunc("POST /people/{id}/unlink", s.personUnlink)
	s.mux.HandleFunc("POST /people/{id}/delete", s.personDelete)
}

type personView struct {
	inventory.Person
	Strip template.HTML
}

type peopleData struct {
	People  []personView
	Devices []inventory.Device
	Window  int // minutes
}

func (s *server) renderPeople(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	ctx := r.Context()
	ps, err := s.Inv.People(ctx)
	if err != nil {
		s.serverError(w, err)
		return
	}
	devs, err := s.Inv.List(ctx)
	if err != nil {
		s.serverError(w, err)
		return
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].DisplayName() < devs[j].DisplayName() })
	now := s.Now()
	labels := make([]string, presenceDays)
	for i := range labels {
		labels[i] = now.AddDate(0, 0, i-(presenceDays-1)).Format("Mon 2")
	}
	d := peopleData{Devices: devs, Window: int(inventory.HomeWindow.Minutes())}
	for _, p := range ps {
		days, err := s.Inv.PresenceDays(ctx, p.ID, presenceDays)
		if err != nil {
			s.serverError(w, err)
			return
		}
		d.People = append(d.People, personView{Person: p, Strip: PresenceStrip(days, labels)})
	}
	s.render(w, r, status, "people", "layout", page{Title: "People", Nav: "people", Error: errMsg, Data: d})
}

func (s *server) peoplePage(w http.ResponseWriter, r *http.Request) { s.renderPeople(w, r, 200, "") }

func (s *server) personAdd(w http.ResponseWriter, r *http.Request) {
	_, err := s.Inv.AddPerson(r.Context(), r.PostFormValue("name"))
	if errors.Is(err, inventory.ErrBadName) {
		s.renderPeople(w, r, http.StatusBadRequest, "Enter a name that is not already used.")
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/people?msg=personadded", http.StatusSeeOther)
}

// personDevice parses the person id from the path and the device id from
// the form. It writes the error response itself.
func (s *server) personDevice(w http.ResponseWriter, r *http.Request) (int64, int64, bool) {
	pid, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return 0, 0, false
	}
	dev, err := strconv.ParseInt(r.PostFormValue("device"), 10, 64)
	if err != nil || dev <= 0 {
		s.renderPeople(w, r, http.StatusBadRequest, "Choose a device.")
		return 0, 0, false
	}
	return pid, dev, true
}

func (s *server) personLink(w http.ResponseWriter, r *http.Request) {
	pid, dev, ok := s.personDevice(w, r)
	if !ok {
		return
	}
	err := s.Inv.LinkDevice(r.Context(), pid, dev)
	if errors.Is(err, inventory.ErrNotFound) {
		s.renderPeople(w, r, http.StatusBadRequest, "That person or device no longer exists.")
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	// Show the right state at once instead of after the next scan.
	if err := s.Inv.EvaluatePresence(r.Context()); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/people?msg=linked", http.StatusSeeOther)
}

func (s *server) personUnlink(w http.ResponseWriter, r *http.Request) {
	pid, dev, ok := s.personDevice(w, r)
	if !ok {
		return
	}
	if err := s.Inv.UnlinkDevice(r.Context(), pid, dev); err != nil && !errors.Is(err, inventory.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	if err := s.Inv.EvaluatePresence(r.Context()); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/people?msg=unlinked", http.StatusSeeOther)
}

func (s *server) personDelete(w http.ResponseWriter, r *http.Request) {
	pid, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	err := s.Inv.DeletePerson(r.Context(), pid)
	if errors.Is(err, inventory.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, fmt.Errorf("delete person: %w", err))
		return
	}
	http.Redirect(w, r, "/people?msg=persondeleted", http.StatusSeeOther)
}
