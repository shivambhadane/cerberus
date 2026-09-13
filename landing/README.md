# landing

Marketing landing page for Cerberus. A single self-contained `index.html` — no build step,
no dependencies, no JavaScript.

```bash
python3 -m http.server 5180 --directory landing
```

Then open http://localhost:5180.

## Deploying

Because it is one static file, it can be served from anywhere. To publish it with GitHub
Pages, enable Pages in the repository settings and point it at this directory (or copy
`index.html` to a `docs/` or `gh-pages` branch root).

## Content

Everything on the page is drawn from this project's own documentation and from real scoring
output — the comparison in the "same scan, ranked two ways" section is an actual result from
a run against a lab host running Apache 2.4.49, not an illustration.

There are deliberately no testimonials, customer logos, or usage statistics: Cerberus has no
users, and inventing social proof would be dishonest.
