// Command mktmpl derives a macOS menu-bar *template* icon from the colour
// brand mark: every pixel is forced to black, the alpha (and its
// anti-aliased edges) is kept. macOS treats a black+alpha image as a
// template and tints it for the light/dark menu bar automatically, so the
// woven mark stays crisp and legible in both — unlike the two-colour weave,
// whose indigo strands wash out on a dark menu bar.
//
//	go run .                       # ../../assets/icon.png -> ../../assets/icon-template.png
//	go run . in.png out.png
package main

import (
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
)

func main() {
	in := "../../assets/icon.png"
	out := "../../assets/icon-template.png"
	if len(os.Args) > 1 {
		in = os.Args[1]
	}
	if len(os.Args) > 2 {
		out = os.Args[2]
	}

	src := decode(in)
	b := src.Bounds()
	dst := image.NewNRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			_, _, _, a := src.At(x, y).RGBA() // 16-bit
			dst.SetNRGBA(x, y, color.NRGBA{0, 0, 0, uint8(a >> 8)})
		}
	}
	encode(out, dst)
	log.Printf("wrote %s (%dx%d, black+alpha template)", out, b.Dx(), b.Dy())
}

func decode(path string) image.Image {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()
	m, err := png.Decode(f)
	if err != nil {
		log.Fatal(err)
	}
	return m
}

func encode(path string, m image.Image) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()
	if err := png.Encode(f, m); err != nil {
		log.Fatal(err)
	}
}
