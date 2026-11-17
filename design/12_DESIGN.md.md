# design.md — CICIoT23 Sentinel Design System Constitution (Fortify360 Dark Suite)
## 1. Product Design Direction
CICIoT23 Sentinel uses a refined, dark-obsidian enterprise security interface directly anchored to the Fortify360 Enterprise IAM reference suite. It pairs a deep `#0D0C14` obsidian-indigo canvas with `#13121D` rounded surface cards (`12px` radius), crisp `1px solid #222030` structural borders, and signature smooth, thick, rounded-cap spline curves and circular ring gauges. All copy and labels strictly follow a Plain-English UI rule—no academic ML jargon or cryptic column names.
## 2. Aesthetic Reference and Visual Anchor
- **Primary Visual Anchor:** Fortify360 Enterprise IAM & Security Dashboard Suite (`Global Enterprise.png`, `Compliance Engine.png`, `Endpoint Management.png`, `Compliance Status.png`).
- **Signature Visual Elements:**
  - Deep obsidian-violet sidebar and canvas (`#0D0C14` / `#100F18`).
  - Elevated dark-slate cards (`#13121D`) with `12px` border radius and `1px solid #222030` hairlines.
  - **Smooth Cubic-Bezier Wave Graphs:** Multi-series spline charts with thick `6px` strokes (`stroke-linecap: round`, `stroke-linejoin: round`), gentle sine-like curvature, and subtle horizontal baseline grid lines (`#1E1D2B`), exactly matching `Login Activity` in `Global Enterprise.png`.
  - **Thick Rounded-Cap Circular Ring Gauges:** `14px` stroke width circular progress rings (`#10B981` emerald or `#06B6D4` cyan arc on a `#1E1D2B` circular track) with centered bold percentage readouts, matching `Control Coverage (84%)` in `Compliance Engine.png`.
  - **Rounded Horizontal Progress Bars & Mini Vertical Bar Equalizers:** `6px`-high rounded progress bars (`9999px` pill ends) inside top KPI cards, and 8-bar mini vertical rounded bar clusters inside device metric cards (`Endpoint Management.png`).
## 3. Core Design Principles
1. **Plain-English Clarity Only:** Never display raw feature variables or complex security buzzwords alone. Use clear terms: `"Auto-Block Attacks"`, `"Block All Internet"`, `"Why This Was Flagged"`, `"SYN-to-ACK Ratio (Unfinished Connections)"`, and `"Packet Size Variation"`.
2. **Smooth, High-Contrast Data Visualization:** Line charts must use smooth cubic-bezier interpolation (`monotoneX` / `catmullRom`) with `5px–6px` rounded strokes so traffic trends are readable from across a room.
3. **Structured Dark Hierarchy:** Contrast is established through subtle surface stepping (`#0D0C14` canvas -> `#13121D` card -> `#1A1826` input/table header) and crisp `1px solid #222030` borders.
4. **Restrained Semantic Color:** Indigo-violet (`#6366F1`) and electric blue (`#2563EB`) drive navigation and primary actions; emerald (`#10B981`), amber (`#F59E0B`), and coral-red (`#EF4444`) strictly communicate `Normal`, `DoS Attack`, and `DDoS Attack / Isolated` states.
## 4. Color Tokens (Exact HEX Values)
| Token | HEX Value | Purpose |
| :--- | :--- | :--- |
| `Background` | `#0D0C14` | Primary application canvas (deep obsidian-indigo) |
| `Sidebar Surface` | `#100F18` | Left navigation rail and bottom system telemetry bar |
| `Surface` | `#13121D` | Primary cards, chart panels, tables, and slide-over drawers |
| `Surface Elevated` | `#1A1826` | Active sidebar item, input fields, code blocks, and table headers |
| `Border` | `#222030` | `1px` structural card borders, table row dividers, and chart gridlines |
| `Border Highlight` | `#3B3854` | Hover/selected card borders and focused inputs |
| `Text Primary` | `#F8FAFC` | Headings, primary metric numbers, and active labels |
| `Text Muted` | `#8E8CA3` | Secondary labels, timestamps, column headers, and helper copy |
| `Primary Action` | `#2563EB` | Primary interactive CTA buttons (`+ Enroll Device`, `Apply`, `Copy Command`) |
| `Brand Indigo` | `#6366F1` | Brand shield badge, primary normal-traffic spline curve (`#6366F1`), active pagination |
| `Success` | `#10B981` | Normal traffic state, Online status, circular ring gauge fill, compliant progress bars |
| `Warning` | `#F59E0B` | Single-source DoS Attack state, medium risk bars, and caution badges |
| `Danger / Coral` | `#F97316` | Secondary attack spline curve (`#F97316` coral-orange wave in `Global Enterprise.png`) |
| `Error / Critical` | `#EF4444` | Multi-source DDoS Attack state, "Block All Internet" button, critical risk bars |
## 5. Typography System
- **Locked Font Family:** `Plus Jakarta Sans` across the entire interface (matching the clean geometric sans-serif numerals and headers in the Fortify360 screens).
- **Numeric Discipline:** Enforce `font-variant-numeric: tabular-nums` on all KPI counters, percentages, IP/MAC addresses, uptimes, packet rates, and table cells.
- **Type Scale & Weights:**
  - `H1`: `28px` / `36px` line-height / `700` (Bold) — Page header titles and large KPI card numbers (`32px`).
  - `H2`: `20px` / `28px` line-height / `600` (SemiBold) — Panel and chart titles (`Login Activity`, `Control Coverage`).
  - `H3`: `16px` / `24px` line-height / `600` (SemiBold) — Sub-panel headers and device card titles.
  - `Body`: `14px` / `22px` line-height / `400` (Regular) & `500` (Medium) — Table cell content, navigation links, and buttons.
  - `Small`: `13px` / `18px` line-height / `500` (Medium) — Card subtitles, filter pills, and form labels.
  - `Caption`: `11px` / `16px` line-height / `600` (SemiBold) / `0.05em` letter-spacing — Table column headers (`TIMESTAMP`, `DEVICE NAME`), KPI card labels, and bottom telemetry bar text.
## 6. Spacing Scale (8px Base)
- `4px`: Inline badge/icon gap.
- `8px`: Compact button group gap and internal pill padding.
- `16px`: Standard input/table cell padding and grid gap between top KPI cards.
- `24px`: Internal card padding (`24px`) and vertical spacing between page rows.
- `32px`: Major section separation.
## 7. Geometry & Component Standards
- **Card Geometry:** `12px` border radius on primary panels and KPI cards; `1px solid #222030` border; flat `#13121D` fill.
- **Button & Input Geometry:** `8px` border radius; `38px` standard height (`32px` for compact table header buttons like `Filter` / `Export CSV`).
- **Chart Specifications (Mandatory):**
  - *Spline Wave Charts:* Smooth cubic-bezier curves (`type="monotone"`), `5px–6px` stroke width, rounded line caps (`strokeLinecap="round"`), no jagged point markers, subtle horizontal dashed/solid grid lines (`#222030`), and clean legend dots (`10px` circles) in the top-right header of the chart card.
  - *Circular Ring Gauges:* `180px × 180px` SVG ring, `14px` stroke width, `#1E1D2B` background track, `#10B981` (or `#06B6D4`) foreground arc with `strokeLinecap="round"`, centered `32px` Bold percentage and `11px` muted label underneath.
  - *KPI Progress Bars:* `6px` height, `#1E1D2B` full-width track, rounded pill ends (`border-radius: 9999px`), filled with `#10B981`, `#6366F1`, `#F59E0B`, or `#EF4444`.
  - *Mini Vertical Bar Equalizers:* 8 vertical rounded bars (`4px` width, `4px` gap, `4px–24px` heights, `2px` radius) placed in the bottom-right corner of endpoint KPI cards.
- **Bottom System Telemetry Footer:** Fixed `32px` bottom bar (`#100F18`, `1px solid #222030` top border) displaying `"■ SYSTEMS OPERATIONAL"`, `"GO AGENT LATENCY: 4MS"`, `"ACTIVE MODEL: XGBOOST (22F)"` on the left, and `"API V2.4.0 · LAST UPDATED: LIVE"` on the right.
## 8. Accessibility & Responsive Behavior
- All text meets WCAG AA contrast on `#0D0C14` and `#13121D` (`#F8FAFC` is `16.4:1`; `#8E8CA3` is `5.3:1`).
- Every colored status dot/bar is paired with explicit text (`Normal`, `DoS Attack`, `DDoS Attack`, `Internet Blocked`).
- Desktop (`>= 1280px`) uses fixed `240px` left sidebar + 12-column content grid; Tablet (`768px–1279px`) wraps 4-card KPI strips into 2×2 grids; Mobile (`< 768px`) stacks cards single-column.