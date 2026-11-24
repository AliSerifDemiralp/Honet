package web

import (
	"html"
	"html/template"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/AliSerifDemiralp/honet/internal/inventory"
)

// Charts are drawn on the server as inline SVG. The Content-Security-Policy
// forbids inline styles, so all styling comes from classes in honet.css.

// Point is one value of a series; Gap marks missing data (the line breaks).
type Point struct {
	At  time.Time
	V   float64
	Gap bool
}

// Series is one line; Class is its CSS class (chart-a, chart-b, ...).
type Series struct {
	Name   string
	Class  string
	Points []Point
}

// Band is a shaded time range, used for internet outages.
type Band struct{ From, To time.Time }

const (
	chartW, chartH      = 720.0, 180.0
	plotL, plotR        = 44.0, 712.0
	plotT, plotB        = 18.0, 156.0
	stripLabelW, stripH = 60.0, 18.0
)

func num(v float64) string { return strconv.FormatFloat(math.Round(v*10)/10, 'f', -1, 64) }

// niceMax rounds v up to 1, 2 or 5 times a power of ten.
func niceMax(v float64) float64 {
	if v <= 0 {
		return 1
	}
	base := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 5, 10} {
		if m*base >= v {
			return m * base
		}
	}
	return 10 * base
}

// LineChart draws series over [from, to] with a 0-based value axis.
func LineChart(title, unit string, from, to time.Time, series []Series, bands []Band) template.HTML {
	esc := html.EscapeString
	span := to.Sub(from).Seconds()
	if span <= 0 {
		span = 1
	}
	maxV := 0.0
	for _, s := range series {
		for _, p := range s.Points {
			if !p.Gap {
				maxV = max(maxV, p.V)
			}
		}
	}
	maxV = niceMax(maxV)
	x := func(t time.Time) float64 {
		f := t.Sub(from).Seconds() / span
		return plotL + math.Max(0, math.Min(1, f))*(plotR-plotL)
	}
	y := func(v float64) float64 { return plotB - math.Max(0, math.Min(1, v/maxV))*(plotB-plotT) }

	var b strings.Builder
	label := esc(title + " (" + unit + ")")
	b.WriteString(`<svg class="chart" viewBox="0 0 720 180" role="img" aria-label="` + label + `" xmlns="http://www.w3.org/2000/svg">`)
	b.WriteString(`<title>` + label + `</title>`)
	for _, band := range bands {
		x0, x1 := x(band.From), x(band.To)
		if x1-x0 < 1 {
			x1 = x0 + 1
		}
		b.WriteString(`<rect class="chart-outage" x="` + num(x0) + `" y="` + num(plotT) + `" width="` + num(x1-x0) + `" height="` + num(plotB-plotT) + `"/>`)
	}
	for i := 0; i <= 4; i++ {
		v := maxV * float64(i) / 4
		yy := num(y(v))
		b.WriteString(`<line class="chart-grid" x1="` + num(plotL) + `" y1="` + yy + `" x2="` + num(plotR) + `" y2="` + yy + `"/>`)
		b.WriteString(`<text class="chart-label" x="` + num(plotL-4) + `" y="` + num(y(v)+3) + `" text-anchor="end">` + esc(strconv.FormatFloat(v, 'g', 4, 64)) + `</text>`)
	}
	loc := from.Location()
	yy, mm, dd := from.Date()
	for d := time.Date(yy, mm, dd, 0, 0, 0, 0, loc); d.Before(to); d = d.AddDate(0, 0, 1) {
		if d.Before(from) {
			continue
		}
		xx := num(x(d))
		b.WriteString(`<line class="chart-grid" x1="` + xx + `" y1="` + num(plotT) + `" x2="` + xx + `" y2="` + num(plotB) + `"/>`)
		b.WriteString(`<text class="chart-label" x="` + num(x(d)+3) + `" y="` + num(plotB+14) + `">` + esc(d.Format("Mon 2")) + `</text>`)
	}
	lx := plotR
	for i := len(series) - 1; i >= 0; i-- {
		s := series[i]
		name := esc(s.Name)
		lx -= float64(len([]rune(s.Name)))*7 + 22
		b.WriteString(`<line class="` + esc(s.Class) + `" x1="` + num(lx) + `" y1="9" x2="` + num(lx+12) + `" y2="9"/>`)
		b.WriteString(`<text class="chart-label" x="` + num(lx+15) + `" y="12">` + name + `</text>`)
	}
	for _, s := range series {
		var run []Point
		flush := func() {
			switch len(run) {
			case 0:
			case 1:
				b.WriteString(`<circle class="` + esc(s.Class) + `" cx="` + num(x(run[0].At)) + `" cy="` + num(y(run[0].V)) + `" r="2"/>`)
			default:
				b.WriteString(`<polyline class="` + esc(s.Class) + `" points="`)
				for i, p := range run {
					if i > 0 {
						b.WriteByte(' ')
					}
					b.WriteString(num(x(p.At)) + "," + num(y(p.V)))
				}
				b.WriteString(`"/>`)
			}
			run = run[:0]
		}
		for _, p := range s.Points {
			if p.Gap {
				flush()
				continue
			}
			run = append(run, p)
		}
		flush()
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// PresenceStrip draws one row per day with the "home" spans filled.
func PresenceStrip(days [][]inventory.Span, labels []string) template.HTML {
	esc := html.EscapeString
	h := float64(len(days)) * stripH
	trackW := chartW - stripLabelW
	var b strings.Builder
	b.WriteString(`<svg class="chart presence" viewBox="0 0 720 ` + num(h) + `" role="img" aria-label="Time at home by day" xmlns="http://www.w3.org/2000/svg">`)
	b.WriteString(`<title>Time at home by day</title>`)
	for i, spans := range days {
		top := float64(i) * stripH
		if i < len(labels) {
			b.WriteString(`<text class="chart-label" x="0" y="` + num(top+13) + `">` + esc(labels[i]) + `</text>`)
		}
		b.WriteString(`<rect class="presence-track" x="` + num(stripLabelW) + `" y="` + num(top+3) + `" width="` + num(trackW) + `" height="12"/>`)
		for _, s := range spans {
			if !s.Home {
				continue
			}
			y, m, d := s.From.Date()
			dayStart := time.Date(y, m, d, 0, 0, 0, 0, s.From.Location())
			dayLen := dayStart.AddDate(0, 0, 1).Sub(dayStart).Seconds()
			x0 := stripLabelW + s.From.Sub(dayStart).Seconds()/dayLen*trackW
			w := s.To.Sub(s.From).Seconds() / dayLen * trackW
			b.WriteString(`<rect class="presence-home" x="` + num(x0) + `" y="` + num(top+3) + `" width="` + num(math.Max(w, 1)) + `" height="12"/>`)
		}
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}
