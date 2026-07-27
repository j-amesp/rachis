# RACHIS — federated intelligence platform demo

`RACHIS.dc.html` is a single self-contained interactive prototype. Open it directly in a browser — no build step. All data is fake (see the "DEMO — SYNTHETIC DATA" badge in the top bar).

## What it demonstrates

- **Search** (top bar) — mixed entity results (vessel/person/org/location) as confidence-ring cards. Try "Northern Star".
- **Graph** workspace — force-directed-style network around NORTHERN STAR: owners, port calls, associated vessels, people. Dashed edges are inferred relationships with a confidence score. Locked-glyph nodes have withheld fields. Click a node to recentre/open its profile; hover for a tooltip.
- **Profile** workspace — NORTHERN STAR's multi-source record: per-field confidence, expandable "N agree / N disputes" provenance, a struck-through superseded prior name, and classification chips (UNMARKED/RESTRICTED/GENERAL/SECRET).
- **Map** workspace — port-call pins, a pulsing AIS last-known-position marker, a locked/withheld precise-position marker, and two friendly assets (patrol vessel + MPA) each showing a live time-to-intercept computed from great-circle distance ÷ speed.
- **RACHIS Assist** (right rail) — dummy AI recommendation cards, clearly labelled generated/inferred, with thumbs up/down.
- **Withheld-field callback (the centerpiece)** — on the profile, "Request via callback" on the withheld precise position opens a 5-stage traffic-light sequence (permissions → request to source → source decision → decrypt → reveal), ending in a synthetic satellite-image payload and a map recompute of intercept times. A GBR/PNA toggle in the modal switches between an approved release and a denial that never contacts the source.

## Assumptions / scope notes

- Left-rail search is folded into the top-bar global search; the left rail itself holds collections + saved queries + the workspace switcher.
- Only NORTHERN STAR has a full profile; other search results open a "limited scope" fallback card.
- The map is a stylized/schematic grid (fictional coordinates chosen for layout), not a geographically precise chart.
- The satellite image in the reveal step is a user-fillable placeholder (drag an image onto it) with a reticle overlay and "SYNTHETIC IMAGERY" watermark — no real imagery is generated.

## Theme

Base `#0F1620`, panels `#161F2B`, borders `#233044`, accent cyan `#3BA9C7`; classification palette UNMARKED grey / RESTRICTED amber / GENERAL teal / SECRET rose. Inter for UI text, JetBrains Mono for identifiers, coordinates, and timestamps.
