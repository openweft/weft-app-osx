// Command mkbg renders the Weft.dmg background: a dark woven "trame" in
// the site's dark-theme palette (deep indigo navy + a basket-weave of warp
// and weft threads), with two soft spotlights under the icon row so the app
// icon and the Applications drop-target stay legible on the dark field, and
// a cyan arrow pointing at the drop target.
//
//	go run .          # writes ../dmg-background.png
//	go run . out.png
//
// Pure stdlib, reproducible.
package main

import (
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
)

// Logical window is 660x420 (matches dmg.sh --window-size). Rendered at 2x.
const (
	scale = 2
	W     = 660 * scale
	H     = 420 * scale

	spacing = 30 * scale // distance between threads
	thick   = 5          // thread thickness (px)

	// Icon centres (logical) — must match dmg.sh --icon / --app-drop-link.
	appX  = 165
	drpX  = 495
	iconY = 250
)

var (
	// Site dark theme (static/css/main.css :root[data-theme="dark"]).
	bgTop = color.RGBA{0x1c, 0x28, 0x4c, 0xff} // ~ --bg #1a2545
	bgBot = color.RGBA{0x15, 0x1d, 0x39, 0xff}
	warpC = color.RGBA{0x24, 0x33, 0x63, 0xff} // --bg-2
	weftC = color.RGBA{0x2e, 0x40, 0x79, 0xff} // --bg-3
	nodeC = color.RGBA{0x22, 0xd3, 0xee, 0xff} // --accent (mesh dots)
	// Spotlight + arrow keep the icons / drop target visible on the dark field.
	spotC  = color.RGBA{0xcf, 0xd8, 0xea, 0xff} // soft light halo
	arrowC = color.RGBA{0x22, 0xd3, 0xee, 0xff} // cyan accent
)

func main() {
	out := "../dmg-background.png"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	img := image.NewRGBA(image.Rect(0, 0, W, H))

	// Gradient base.
	for y := 0; y < H; y++ {
		t := float64(y) / float64(H)
		c := lerp(bgTop, bgBot, t)
		for x := 0; x < W; x++ {
			img.SetRGBA(x, y, c)
		}
	}

	// Woven trame.
	var xs, ys []int
	for x := spacing / 2; x < W; x += spacing {
		xs = append(xs, x)
	}
	for y := spacing / 2; y < H; y += spacing {
		ys = append(ys, y)
	}
	for _, x := range xs {
		fillRect(img, x-thick/2, 0, x-thick/2+thick, H, warpC, 0.55)
	}
	for _, y := range ys {
		fillRect(img, 0, y-thick/2, W, y-thick/2+thick, weftC, 0.6)
	}
	for i, x := range xs {
		for j, y := range ys {
			if (i+j)%2 == 0 { // interlace: warp over weft on a checkerboard
				fillRect(img, x-thick/2, y-thick/2-1, x-thick/2+thick, y-thick/2+thick+1, warpC, 0.7)
			}
			if i%4 == 1 && j%4 == 1 { // sparse cyan mesh nodes
				dot(img, float64(x), float64(y), 2.2*scale, nodeC, 0.16)
			}
		}
	}

	// Soft spotlights behind the two icons (centred a little low so the
	// icon *and* its Finder label below sit on the lighter area).
	glow(img, appX*scale, (iconY+18)*scale, 104*scale, spotC, 0.50)
	glow(img, drpX*scale, (iconY+18)*scale, 104*scale, spotC, 0.50)

	// Cyan arrow pointing at the Applications drop target.
	drawArrow(img,
		float64((appX+66)*scale), float64(iconY*scale),
		float64((drpX-66)*scale), float64(iconY*scale),
		arrowC, 3*scale)

	save(img, out)
	log.Printf("wrote %s (%dx%d)", out, W, H)
}

// --- helpers --------------------------------------------------------------

func lerp(a, b color.RGBA, t float64) color.RGBA {
	li := func(p, q uint8) uint8 { return uint8(float64(p) + (float64(q)-float64(p))*t) }
	return color.RGBA{li(a.R, b.R), li(a.G, b.G), li(a.B, b.B), 0xff}
}

func fillRect(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA, a float64) {
	for y := y0; y < y1; y++ {
		for x := x0; x < x1; x++ {
			blend(img, x, y, c, a)
		}
	}
}

// glow paints a soft radial halo (brightest at the centre, fading out).
func glow(img *image.RGBA, cx, cy int, r int, c color.RGBA, peak float64) {
	rf := float64(r)
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			d := math.Hypot(float64(x-cx), float64(y-cy))
			if d >= rf {
				continue
			}
			f := 1 - d/rf
			blend(img, x, y, c, peak*f*f) // quadratic falloff
		}
	}
}

func drawArrow(img *image.RGBA, x0, y0, x1, y1 float64, c color.RGBA, w int) {
	steps := int(math.Hypot(x1-x0, y1-y0))
	for i := 0; i <= steps; i++ {
		t := float64(i) / float64(steps)
		disc(img, x0+(x1-x0)*t, y0+(y1-y0)*t, float64(w)/2, c)
	}
	ang := math.Atan2(y1-y0, x1-x0)
	head := float64(11 * scale)
	for _, da := range []float64{0.5, -0.5} {
		hx := x1 - head*math.Cos(ang+da)
		hy := y1 - head*math.Sin(ang+da)
		hsteps := int(head)
		for i := 0; i <= hsteps; i++ {
			t := float64(i) / float64(hsteps)
			disc(img, x1+(hx-x1)*t, y1+(hy-y1)*t, float64(w)/2, c)
		}
	}
}

func disc(img *image.RGBA, cx, cy, r float64, c color.RGBA) {
	for y := int(cy - r - 1); y <= int(cy+r+1); y++ {
		for x := int(cx - r - 1); x <= int(cx+r+1); x++ {
			d := math.Hypot(float64(x)-cx, float64(y)-cy)
			switch {
			case d <= r:
				blend(img, x, y, c, 1)
			case d <= r+1:
				blend(img, x, y, c, r+1-d)
			}
		}
	}
}

func dot(img *image.RGBA, cx, cy, r float64, c color.RGBA, a float64) {
	for y := int(cy - r - 1); y <= int(cy+r+1); y++ {
		for x := int(cx - r - 1); x <= int(cx+r+1); x++ {
			dd := (float64(x)-cx)*(float64(x)-cx) + (float64(y)-cy)*(float64(y)-cy)
			if dd <= r*r {
				blend(img, x, y, c, a)
			}
		}
	}
}

func blend(img *image.RGBA, x, y int, c color.RGBA, a float64) {
	if x < 0 || y < 0 || x >= W || y >= H || a <= 0 {
		return
	}
	if a > 1 {
		a = 1
	}
	o := img.RGBAAt(x, y)
	mix := func(s, d uint8) uint8 { return uint8(float64(s)*a + float64(d)*(1-a)) }
	img.SetRGBA(x, y, color.RGBA{mix(c.R, o.R), mix(c.G, o.G), mix(c.B, o.B), 0xff})
}

func save(img image.Image, path string) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}
