# PNG Conversion Guide

This directory contains SVG files optimized for PNG conversion. To generate the actual PNG files, use one of the following methods:

## Method 1: Using Inkscape (Recommended)

```bash
# Install Inkscape if not already installed
# Ubuntu/Debian: sudo apt install inkscape
# macOS: brew install inkscape
# Windows: Download from https://inkscape.org/

# Convert SVG to PNG
inkscape logo.svg --export-type=png --export-filename=logo.png --export-width=512 --export-height=512
inkscape logo-small.svg --export-type=png --export-filename=logo-small.png --export-width=64 --export-height=64
inkscape logo-large.svg --export-type=png --export-filename=logo-large.png --export-width=1024 --export-height=1024
inkscape favicon-32.svg --export-type=png --export-filename=favicon-32.png --export-width=32 --export-height=32
inkscape favicon-16.svg --export-type=png --export-filename=favicon-16.png --export-width=16 --export-height=16
```

## Method 2: Using ImageMagick

```bash
# Install ImageMagick if not already installed
# Ubuntu/Debian: sudo apt install imagemagick
# macOS: brew install imagemagick
# Windows: Download from https://imagemagick.org/

# Convert SVG to PNG
convert logo.svg -resize 512x512 logo.png
convert logo-small.svg -resize 64x64 logo-small.png
convert logo-large.svg -resize 1024x1024 logo-large.png
convert favicon-32.svg -resize 32x32 favicon-32.png
convert favicon-16.svg -resize 16x16 favicon-16.png
```

## Method 3: Using rsvg-convert

```bash
# Install librsvg if not already installed
# Ubuntu/Debian: sudo apt install librsvg2-bin
# macOS: brew install librsvg
# Windows: Available through MSYS2

# Convert SVG to PNG
rsvg-convert -w 512 -h 512 logo.svg -o logo.png
rsvg-convert -w 64 -h 64 logo-small.svg -o logo-small.png
rsvg-convert -w 1024 -h 1024 logo-large.svg -o logo-large.png
rsvg-convert -w 32 -h 32 favicon-32.svg -o favicon-32.png
rsvg-convert -w 16 -h 16 favicon-16.svg -o favicon-16.png
```

## Method 4: Online Conversion

For quick conversion without installing tools:
1. Visit https://convertio.co/svg-png/ or similar online converter
2. Upload the SVG file
3. Set the desired dimensions
4. Download the PNG result

## File Specifications

- **logo.png**: 512x512px - Primary documentation logo
- **logo-small.png**: 64x64px - Inline usage
- **logo-large.png**: 1024x1024px - Headers and large displays
- **favicon-32.png**: 32x32px - Standard favicon
- **favicon-16.png**: 16x16px - Small favicon

All PNG files should have transparent backgrounds and maintain the Deep Forest Green (#1B4332) color scheme.