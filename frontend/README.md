# frontend

The Cerberus dashboard: React 18, TypeScript, Vite. No router, state, or UI library: about 2,700 lines
(including the stylesheet) that depend only on React.

```bash
npm install
npm run dev          # http://localhost:5173/platform/   (the landing page is at /)
npm run build        # type-checks, then bundles to dist/
npm run test:e2e     # real-browser end-to-end + accessibility test (see below)
```

The API must be running and must allow this origin (`CORS_ORIGINS` in `.env` already lists
`http://localhost:5173` and `http://127.0.0.1:5173`). Set `API_SECRET_KEY` in the repo's `.env`, then:

```bash
uvicorn api.main:app --port 8000
```

On first load the dashboard asks you to sign in or create an account, with Google, GitHub or email
(Firebase Authentication; the API verifies the token). Point it at another API with `VITE_API_URL`.
The Firebase web configuration is read from `VITE_FIREBASE_*` and falls back to the values in
`src/lib/firebase.ts`. Those are public identifiers, not secrets, but to use your own Firebase project set
all of them (and `FIREBASE_PROJECT_ID` on the API).

### How the session is held

The access token lives in a module variable and **nowhere else** — not in `localStorage`, where any
script on the page could read it. Reloading the page loses it and the client silently gets a new one
from the refresh cookie, which the browser holds as httpOnly. A request that comes back 401 triggers
one refresh and a retry, so an expiring token is invisible to the person using the dashboard; if the
refresh is refused, the app returns to the sign-in screen with "Your session ended."

The only thing kept in `localStorage` is a non-secret flag saying this browser has signed in before,
so a first-time visitor does not fire a refresh request that is bound to fail.

## Screens

The shell has three parts. The **sidebar** holds the product name (a label, **not** a link: it does not
leave the dashboard) and the navigation, grouped as *Workspace* (Overview, Targets, Scans) and *Results*
(Findings, Assets, Evidence); on phones it becomes a compact bar across the top. The **top bar** shows where
you are, a **Landing page** button (the only way back to the public site), and your account: your photo
and name, which open Profile, and Sign out. Every screen has a page header with one `h1` and a sentence on
what the screen is for.

| Screen | What it is for |
|---|---|
| **Targets** | What you can scan, and how you prove it is yours. Choose **Custom domain** (claim it, then publish the exact DNS TXT record shown, with copy buttons and a **Check verification** button; a record that has not propagated yet is a normal state, not an error) or **Deployment** (for an app on `*.vercel.app`, `*.netlify.app` or `*.pages.dev`: connect Vercel, Netlify or Cloudflare, pick a project, **Add & verify**). A provider the server has not set up says so. Where the server supports it (Vercel), **Use an access token** offers a paste-a-token form instead of OAuth, with the trade-off spelled out; the token is cleared from the page as soon as it is sent. A target verified through a platform shows "via Vercel" (or the like) instead of a DNS record. Tokens never reach the browser: it only ever sees that an account is connected. See [../docs/API.md §4](../docs/API.md#4-deployment-providers). |
| **Profile** | Your photo, name, email, how you signed in and when, and the deployment accounts you have connected. The name and photo come from your sign-in provider's verified token (a Google photo follows the change you make to your Google profile on your next sign-in); with no photo, or one that fails to load, it shows your initials. Reached from your name in the top bar. |
| **Overview** | The landing page. Four KPI cards (active findings, actively exploited, confirmed, assets), the **Top risks** as cards that open the finding, a **Risk breakdown** chart (by score band, and confirmed vs inferred), and **Recent scans**. Every number links to the list it counts. Refreshes itself while a scan is running. |
| **Findings** | The ranked list. Search by CVE or host; filter by status, evidence (confirmed / inferred), minimum risk, actively-exploited; sort by risk, CVSS or EPSS; 25 per page. Selecting a finding opens a detail panel with the reasoning, the evidence, a status control, and the asset's criticality. |
| **Assets** | Hosts and ports with their technology. Each shows its criticality and whether that is **inferred** (a guess from the hostname) or **set by you**, editable in place; saving re-ranks that asset's findings straight away. |
| **Evidence** | Raw tool output, exactly as recorded before Cerberus normalized it, narrowable to one asset or one scan. |
| **Scans** | Start a scan against one of your **verified** domains (with the profile picker and its opt-in gate) and browse scan history, including the warnings a scan finished with. There is no "I am authorised" checkbox: the verified domain is the authorisation. With no verified target, this screen sends you to Targets. |
| **Test Labs** | A fixed list of sanctioned public benchmark sites (Acunetix TestASP/TestPHP, IBM Altoro Mutual) and local Docker labs (the built-in Apache CVE lab, OWASP Juice Shop, DVWA), each with its known vulnerabilities, the Docker command to start it, and an **Add as target** button that verifies it instantly — no DNS, no platform account. **Known issue:** this screen has not had its accessibility pass yet; see [Known gaps](#known-gaps). |

Filters, sort, page, and the selected finding all live in the URL (`#/findings?status=active&sort=cvss_score&finding=…`),
so a view can be linked, reloaded, and walked with the back button. The Overview's cards and KPI links
are ordinary links into those URLs.

The layout follows the reference dashboard in [../docs/design/](../docs/design/) (light surfaces, a
sidebar, KPI cards, card lists, a dark primary button). Only those layout patterns were taken; the
name, colours, copy and marks are Cerberus's own.

## Structure

```
src/
├── App.tsx                  shell: skip link, sidebar, top bar, sign-in gate, landmarks
├── api.ts                   typed client for every endpoint; session handling (token, refresh, retry)
├── types.ts                 shapes matching the API
├── styles.css               the design system (tokens, components; nothing else is styled)
├── lib/
│   ├── router.ts            ~70-line hash router (screen + query params)
│   ├── useApi.ts            fetch hook that cancels stale requests
│   └── format.ts            dates, durations, percentages
└── components/
    ├── ui.tsx               shared primitives: Badge, Banner, PageHeader, SortHeader, Pagination, ...
    ├── icons.tsx            the inline icon set (decorative)
    ├── AuthGate.tsx         sign in / create account (Google, GitHub, email)
    ├── Avatar.tsx           the person's photo, or their initials
    ├── ProfileView.tsx      the Profile page
    ├── DomainsView.tsx      "Targets": custom domain (DNS record) or deployment
    ├── DeploymentProviders.tsx  connect Vercel / Netlify / Cloudflare, pick a project, Add & verify
    ├── TestLabsView.tsx     "Test Labs": sanctioned public benchmarks and Docker labs, verified instantly
    ├── OverviewView.tsx  FindingsView.tsx  FindingDetail.tsx  CriticalityEditor.tsx
    ├── AssetsView.tsx  ObservationsView.tsx  ScansView.tsx  EnrichmentBanner.tsx
e2e/dashboard.e2e.cjs        the browser test
```

## Design system

Defined in [src/styles.css](src/styles.css). Components use tokens, never literals: a new colour or
size is added there first.

| | |
|---|---|
| **Colour** | Surfaces (`--bg`, `--surface`, `--surface-2`, `--surface-selected`), text (`--text`, `--text-muted`), accent, and four status hues (danger, warning, success, info), each as a solid, a readable *text* variant, and a tint. Chart bars have their own `--bar-*` tokens |
| **Type** | 12 / 13 / 14 / 16 / 20 / 24 / 32 px (32 is for KPI figures only). **12px is the floor**; nothing is smaller |
| **Spacing** | a 4px grid, `--space-1` … `--space-7` |
| **Controls** | 40px tall, 44px where the pointer is coarse; on a phone the nav targets are 52px |
| **Focus** | a 2px ring on every interactive element via `:focus-visible` |

Components: **Button** (primary / secondary / ghost, default / sm), **Field** (input, select, check),
**Badge** (danger / warning / success / info / neutral), **Banner** (info / warning / error / success),
**Panel**, **KPI card**, **Risk card**, **Bar list**, **Table** (scrolling, focusable wrapper; sortable
headers), **Sidebar nav**, **Page header**, **Pagination**, **Empty state**, **Skeleton**.

### Contrast, measured

Every text and background pairing was computed against WCAG 2.1 AA rather than eyeballed (the worst case
across every surface, including the selected table row and each status tint).

| | Measured | Requirement |
|---|---|---|
| Lowest text ratio | 4.79:1 | 4.5:1 |
| Form-control borders (worst surface) | 3.67:1 | 3:1 |
| Chart bars against their track | 3.64:1 | 3:1 |

`--border` is decorative only; anything that identifies a control uses `--border-strong`.

The raw status hues failed on their own tinted backgrounds (the `KEV` badge measured 4.03:1 and the risk
score on a selected row 4.45:1, against a 4.5:1 requirement), so text on a tint uses a separate `*-text`
variant.

### The Overview chart

A pie or donut was rejected: with five bands that differ by orders of magnitude (5 / 2 / 18 / 111), angles
are the hardest thing for a reader to compare. It is a horizontal bar per band instead: bars start at zero,
are scaled to the share of active findings, and each carries its count and percentage as text. The list
holds all the data, so nothing depends on colour or on seeing the bar (the bar itself is `aria-hidden`).
The chart titles state the finding ("7 of 136 active findings are high or critical") rather than the topic.

## Accessibility

Audited against WCAG 2.1 AA with axe-core plus manual checks. **Zero axe violations on every screen
except Test Labs** (added after the last full audit): that screen has a contrast failure (2.09:1 on the
vulnerability pills, against a 4.5:1 requirement, and 11px text below this design system's own 12px
floor), a heading-level skip, and docker-command blocks that scroll but are not keyboard-reachable. See
[Known gaps](#known-gaps).

- Landmarks (the sidebar `aside`, a top bar `header`, a labelled primary `nav`, `main`), one `h1`, a skip link, and a per-screen
  document title. The current screen is marked with `aria-current="page"`.
- Every table row is operable from the keyboard through a real button in its first cell; the row click
  is only a mouse convenience. Sortable headers expose `aria-sort`.
- Top-risk cards are links whose accessible name says what they open ("CVE-2021-41773 on host:18081, risk
  score 83.6. Show detail.").
- Selecting a finding moves focus into the detail panel; **Escape** closes it and returns focus to the
  row it came from.
- Scrolling tables sit in a focusable, labelled region, so keyboard users can scroll them.
- Status is never colour alone: badges carry text, and the KEV/score badges add screen-reader text.
- Results counts, saves, and scan state are announced through polite live regions; errors use `role="alert"`.
- No page-level horizontal scroll at 200% zoom or at 390px; on a phone the five destinations sit across the
  top, icon over label, all reachable without scrolling.
- `prefers-reduced-motion` is respected.

## The end-to-end test

`npm run test:e2e` drives a real Chrome through 121 checks: creating an account, a failed sign-in,
session persistence across a reload, cookie flags, signing out and back in, the shell (the brand is not a link;
the Landing page button), the Profile page, the Targets page in both modes (a server with no OAuth app: Vercel offers an access token, Netlify and Cloudflare say
they are not set up), claiming and verifying a domain,
a second account that must see none of the first one's data, the skip link, sidebar navigation and
the back button, the Overview (KPI figures, Top risks ordering and links, that both charts add up to the
active total, Recent scans), the keyboard model, URL state, sorting,
search, pagination, the finding panel, editing criticality end to end (down then up, so it passes on any
starting state), evidence-by-asset, the scan form's gating, reflow, and an axe scan of every screen.

It expects the API running against a database populated by the [lab](../lab/README.md) scan. It
**creates accounts and edits an asset's criticality**, and it runs `scripts/claim_legacy.py` to hand the
lab data to the account it just made, so point everything at a copy, and use a **fresh copy for each run**
(the lab data is handed to only one account):

```bash
cp lab.db /tmp/e2e.db
export DATABASE_URL=sqlite:////tmp/e2e.db   # the API *and* the test process need this
uvicorn api.main:app --port 8000
npm run test:e2e
# another origin: E2E_WEB=http://localhost:5190 E2E_API=http://localhost:8010 npm run test:e2e
```

**It does not sign in through the Firebase form**, because that would create real accounts in a real
Firebase project. It creates the account and signs in through the API's local email/password endpoints,
which set the same refresh cookie the dashboard restores a session from. So the Firebase sign-in itself
(Google, GitHub, the email form) is not covered by this test; neither is a real OAuth connection to Vercel,
Netlify or Cloudflare: the provider flows have their own checks with the platform side mocked (see
[../docs/VALIDATION.md](../docs/VALIDATION.md)).

One step reaches around the UI: a test cannot publish a DNS record, so after checking that an unverified
domain stays unverified, it marks the domain verified in the database and carries on through the UI.

It never starts a scan; the form is only checked for its gating rules. Screenshots land in
`e2e/artifacts/` (git-ignored).

## Known gaps

- No unit or component tests; coverage is the end-to-end test above.
- The Overview shows the current state only. There is no trend over time, because Cerberus does not yet
  keep per-scan snapshots of the counts.
- No email verification or password reset in the local login yet, and no "sign out everywhere" control.
- The Profile page is read-only: name and photo come from the sign-in provider and are not editable here.
- **Test Labs has not had an accessibility pass** (see [Accessibility](#accessibility) above) or the design
  review the rest of the dashboard went through.
- Adding a Test Labs target through `scripts/add_test_target.py` directly (rather than the dashboard's
  own "Add as target" button) records it as `dns_txt`-verified, which is not true — it bypasses proof
  entirely. Use the dashboard button, which correctly records `verification_method: "testbed"`.
