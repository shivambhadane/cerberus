# landing

Marketing landing page for Cerberus. A single `index.html` — no build step, no JavaScript,
no framework. The only external request is a Google Fonts stylesheet (Space Grotesk, Inter,
JetBrains Mono); every font has a system fallback, so the page still reads correctly offline.

```bash
python3 -m http.server 5180 --directory landing
```

Then open http://localhost:5180.

## Deploying

Because it is one static file, it can be served from anywhere. To publish it with GitHub
Pages, enable Pages in the repository settings and point it at this directory (or copy
`index.html` to a `docs/` or `gh-pages` branch root).

## Design

Light "paper" ground with alternating dark bands, a blueprint frame (corner ticks, vertical
guide rules, monospace section slugs), oversized display type with an accent-coloured phrase
per heading, and pill buttons with circular arrow badges. The layout idiom is borrowed from
contemporary security-vendor marketing sites; the content, palette, and typography are
Cerberus's own.

## Content

Everything on the page is drawn from this project's own documentation and from real scoring
output — the comparison in the "same scan, ranked two ways" section is an actual result from
a run against a lab host running Apache 2.4.49, not an illustration.

There are deliberately no testimonials, customer logos, or usage statistics: Cerberus has no
users, and inventing social proof would be dishonest.
