---
name: oidc-primitive docs
description: Spec-cited OAuth 2.1 and OpenID Connect security primitives for TypeScript servers
colors:
  bg: "#121310"
  bg-light: "#fbfaf5"
  fg: "#f3f1e8"
  fg-light: "#121310"
  gray-2: "#c3c5ba"
  gray-3: "#b3b5aa"
  gray-4: "#7d8076"
  gray-5: "#3d3f38"
  gray-6: "#1f201c"
  hairline: "#2c2e28"
  accent: "#63d2c1"
  accent-light: "#0f766a"
  accent-low: "color-mix(in srgb, #63d2c1 16%, #121310)"
  code-bg: "#171814"
typography:
  display:
    fontFamily: "IBM Plex Sans Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(2.6rem, 6.2vw, 4.75rem)"
    fontWeight: 650
    lineHeight: 1.02
    letterSpacing: "-0.035em"
  headline:
    fontFamily: "IBM Plex Sans Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "clamp(1.6rem, 3vw, 2.1rem)"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  body:
    fontFamily: "IBM Plex Sans Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.75
  label:
    fontFamily: "IBM Plex Mono, ui-monospace, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
    letterSpacing: "0.12em"
  code:
    fontFamily: "IBM Plex Mono, ui-monospace, monospace"
    fontSize: "0.875rem"
    fontWeight: 400
rounded:
  sm: "0.3rem"
  md: "0.5rem"
  lg: "0.75rem"
  pill: "999px"
spacing:
  content-width: "46rem"
  section: "3.5rem 0 1rem"
  card-padding: "0.85rem 1rem"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.bg}"
    rounded: "{rounded.pill}"
    padding: "0 1.15rem"
    height: "2.75rem"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.fg}"
    rounded: "{rounded.pill}"
    padding: "0 1.15rem"
    height: "2.75rem"
  chip:
    backgroundColor: "transparent"
    textColor: "{colors.gray-2}"
    rounded: "{rounded.pill}"
    typography: "{typography.label}"
  code-panel:
    backgroundColor: "{colors.code-bg}"
    textColor: "{colors.fg}"
    rounded: "{rounded.md}"
    borderColor: "{colors.hairline}"
  matrix-lib-cell:
    backgroundColor: "{colors.accent-low}"
    textColor: "{colors.gray-2}"
    padding: "{spacing.card-padding}"
  diagram-canvas:
    backgroundColor: "{colors.bg}"
    textColor: "{colors.fg}"
    rounded: "{rounded.lg}"
    padding: "1.25rem"
---

# Design

## Overview

North Star: the engineering logbook. A dark, quiet, precise surface where every claim carries a citation. The world is pinned to yielded.dev's grammar (warm near-black, cream type, IBM Plex, hairline rules, bordered code panels, pill chips with one dot) with our own mark and a cool teal accent. One accent color, rationed by role: it marks what the library checks and what is interactive. Mode is Read.

## Colors

Dark is the default: engineers read these pages indoors, late, next to an editor with a dark theme. Light mode is the carbon copy of the same page, not a separate world. One accent (teal) carries every interactive and verified element; red is reserved for error semantics in code only. Neutrals are warm, never blue-gray.

## Typography

IBM Plex Sans Variable for display and body; IBM Plex Mono for code, kickers, spec references and labels. Display sits at 650 with -0.03 to -0.035em tracking. Body measure is 46rem. Mono in running prose only for identifiers; never as costume.

## Layout

Landing: full-width sections separated by hairlines, one idea per section, first viewport is the offer plus the install chip. Docs pages: Starlight content column at 46rem. The ownership matrix and status grids are the only wide elements. Mobile drops to a single column and hides the hero mark.

## Elevation & Depth

Flat. A 1px hairline border is the only edge; no shadows. The one exception is the lib cell's 1px inset accent line. Depth comes from tonal layering (bg, gray-6, code-bg).

## Shapes

Radius vocabulary: 0.3rem inline code, 0.5rem code panels, 0.75rem figures and diagram canvases, pill for buttons and chips. The mark is a key ring: circle plus shaft plus one teal tooth.

## Components

Buttons: pill, 2.75rem, primary filled teal, ghost hairline. Chips: mono, hairline, one accent dot. Code panels: Expressive Code with the mono font, hairline border, transparent shadow, file tab with a teal bottom indicator. Diagrams: Pele SVGs themed through `--pele-*` variables mapped to the same tokens (fg, gray-3, gray-5, gray-6, code-bg, accent), fixed size, scroll on narrow screens. Figures: hairline border, 0.75rem radius.

## Do's and Don'ts

- Do cite the RFC section next to every rule the library enforces.
- Do keep one accent and ration it by role.
- Don't add a kicker or eyebrow label above a heading.
- Don't use emoji or Unicode glyphs as icons; draw SVG in one stroke weight.
- Don't photograph or illustrate the subject; geometry and typography only.
- Don't tint secondary text gray on colored fills; tint from the fill hue.
