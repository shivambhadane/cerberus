/**
 * End-to-end and accessibility test for the dashboard, driven through a real Chrome.
 *
 * WHAT IT NEEDS
 *   - the API running against a database populated by the lab scan (see lab/README.md): it
 *     asserts on that data (136 findings, 5 actively exploited, one probe-confirmed finding,
 *     2 assets, five observations)
 *   - `npm run dev` serving the dashboard on :5173 (E2E_WEB / E2E_API override the two origins)
 *   - DATABASE_URL exported to this process too, and equal to the API's: the test creates an account,
 *     then runs scripts/claim_legacy.py (to give that account the lab data) and a small seed (to mark
 *     a domain verified, since DNS cannot be published from a test)
 *
 * SIGN-IN: the dashboard signs people in with Firebase (Google, GitHub, email), and driving that form
 * would create real accounts in a real Firebase project. So this test signs in through the API's local
 * email/password endpoints instead (`/api/v1/auth/register`, `/login`), which set the same refresh
 * cookie the dashboard picks its session back up from. The Firebase sign-in itself is not covered here.
 *   - Google Chrome installed (it uses the system browser, so there is nothing to download)
 *
 * PROVIDERS: start the API with PROVIDER_TOKEN_ENCRYPTION_KEY set and NO provider credentials (blank
 *     VERCEL, NETLIFY and CLOUDFLARE variables in its environment), so the Targets page is checked in its
 *     "OAuth not set up, access token available" state and nothing here can reach a real platform.
 *
 * WARNING: it creates accounts and edits an asset's criticality. Point the API at a COPY:
 *     cp lab.db /tmp/e2e.db
 *     export DATABASE_URL=sqlite:////tmp/e2e.db
 *     uvicorn api.main:app --port 8000
 *
 * RUN:   npm run test:e2e        (E2E_PYTHON=/path/to/python if it is not .venv/bin/python)
 *
 * It never starts a scan: the scan form is only checked for its gating rules.
 */
const path = require("path");
const fs = require("fs");
const { execFileSync } = require("child_process");
const { chromium } = require("playwright-core");
const axeSource = fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const SP = process.env.E2E_OUT || path.join(__dirname, "artifacts");
if (!process.env.DATABASE_URL) {
  console.error("Set DATABASE_URL to the same database the API is using (a COPY of lab.db).");
  process.exit(2);
}
fs.mkdirSync(SP, { recursive: true });

const WEB = process.env.E2E_WEB || "http://localhost:5173";
const API = process.env.E2E_API || "http://localhost:8000";
const ROOT = path.resolve(__dirname, "..", "..");
const PY = process.env.E2E_PYTHON ||
  (fs.existsSync(path.join(ROOT, ".venv/bin/python")) ? path.join(ROOT, ".venv/bin/python") : "python3");
const py = (...args) => execFileSync(PY, args, { cwd: ROOT, env: process.env, encoding: "utf8" });

const RUN = Date.now();
const EMAIL = `e2e-${RUN}@example.com`;
const NAME = `e2e-${RUN}`; // no name was given, so the dashboard shows the part before the @
const PASSWORD = "correct horse battery staple";
const DOMAIN = `e2e-${RUN}.example.test`;

const results = [];
const check = (name, ok, detail = "") => {
  results.push(ok);
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  -> " + detail : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const browser = await chromium.launch({ channel: "chrome" });
  // Run as a viewer in India (UTC+5:30): the timezone in which "6 h ago" once appeared for a scan started now.
  const ctx = await browser.newContext({ viewport: { width: 1360, height: 900 }, timezoneId: "Asia/Kolkata" });
  const page = await ctx.newPage();
  const problems = [];
  page.on("pageerror", (e) => problems.push("pageerror: " + e.message));
  page.on("console", (m) => { if (m.type() === "error") problems.push("console: " + m.text()); });

  const axe = async (label) => {
    await page.evaluate(axeSource);
    const r = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }));
    check(`axe: ${label} has no violations`, r.violations.length === 0,
      r.violations.map((v) => `${v.id}(${v.nodes.length})`).join(", "));
    return r;
  };
  const hash = () => page.evaluate(() => window.location.hash);
  // Navigate by URL and wait until the destination has actually rendered. Every screen has a
  // table, so waiting on "tbody tr" alone can match the screen we just left.
  const go = async (route, title) => {
    await page.goto(`${WEB}/platform/#/${route}`, { waitUntil: "networkidle" });
    await page.waitForFunction((t) => document.querySelector("h1")?.textContent === t, title);
  };

  // ------------------------------------------------------------------ accounts
  await page.goto(`${WEB}/platform/`, { waitUntil: "networkidle" });
  await page.waitForSelector('h2:has-text("Sign in")');
  check("a signed-out visitor sees the sign-in form and no data", (await page.locator(".nav").count()) === 0);
  check("the sign-in page has one h1 and a main landmark", (await page.locator("h1").count()) === 1 && (await page.locator("main").count()) === 1);
  await axe("sign-in");

  // The API's own sign-in rules, checked directly (the dashboard's form is Firebase's, see the header)
  const weak = await ctx.request.post(`${API}/api/v1/auth/register`, { data: { email: EMAIL, password: "abc" } });
  check("a weak password is refused with the reason", weak.status() === 400 && /at least 5/i.test(await weak.text()));
  const bad = await ctx.request.post(`${API}/api/v1/auth/login`, { data: { email: "nobody@example.com", password: "definitely wrong password" } });
  check("bad credentials get one generic 401", bad.status() === 401 && /incorrect/i.test(await bad.text()));
  const reg = await ctx.request.post(`${API}/api/v1/auth/register`, { data: { email: EMAIL, password: PASSWORD } });
  check("registering creates the account and sets the refresh cookie", reg.status() === 201);
  // The flag the dashboard sets after a sign-in, so it knows to try the refresh cookie. Set once (not on
  // every load) so that signing out really clears it, as it does for a person.
  await page.evaluate(() => localStorage.setItem("cerberus.hadSession", "1"));
  await page.reload({ waitUntil: "networkidle" });
  await page.waitForSelector(".nav-link");
  check("a valid session signs the person in", (await page.locator(".account-link").innerText()).includes(NAME));
  await page.waitForSelector("text=Nothing has been scanned yet");
  check("a new account starts empty and points at the first step",
    /Nothing has been scanned yet/.test(await page.locator("main").innerText()) &&
    (await page.locator('a:has-text("Add a domain")').count()) === 1);

  // The account has no data of its own; hand it the lab's, then prove the session survives a reload
  // (the access token lives in memory, so this is the refresh cookie doing its job).
  py("scripts/claim_legacy.py", EMAIL);
  await page.reload({ waitUntil: "networkidle" });
  await page.waitForSelector(".kpi");
  check("a reload keeps the session (silent refresh from the httpOnly cookie)", (await page.locator(".account-link").innerText()).includes(NAME));
  const cookies = await ctx.cookies();
  const refresh = cookies.find((c) => c.name === "cerberus_refresh");
  check("the refresh cookie is httpOnly and SameSite=Lax", Boolean(refresh) && refresh.httpOnly && refresh.sameSite === "Lax");
  check("no token or password is kept in page storage", await page.evaluate(() =>
    !JSON.stringify({ ...localStorage, ...sessionStorage }).match(/eyJ|password|token/i)));
  problems.length = 0; // the 401 from the deliberate wrong-password step

  // ------------------------------------------------------------------ landmarks, skip link, navigation
  check("has a main landmark", (await page.locator("main").count()) === 1);
  check("has one top bar and one labelled primary nav", (await page.locator("header.topbar").count()) === 1 && (await page.locator('nav[aria-label="Primary"]').count()) === 1);
  check("has exactly one h1", (await page.locator("h1").count()) === 1);
  check("lands on the Overview", (await page.locator("h1").innerText()) === "Overview" && /Overview · Cerberus/.test(await page.title()), await page.title());

  await go("overview", "Overview");
  await page.reload({ waitUntil: "networkidle" }); // a fresh load, so focus starts at the top
  await page.waitForSelector(".kpi");
  await page.keyboard.press("Tab");
  check("the first Tab stop is the skip link", (await page.evaluate(() => document.activeElement.textContent)) === "Skip to content");
  await page.keyboard.press("Enter");
  check("the skip link moves focus to the main content", await page.evaluate(() => document.activeElement.id === "main"));

  const links = await page.locator(".nav-link").allTextContents();
  check("six destinations in the sidebar (Profile lives with the account, not here)", links.join(",") === "Overview,Targets,Scans,Findings,Assets,Evidence", links.join(","));
  check("the current page is marked with aria-current", (await page.locator('.nav-link[aria-current="page"]').innerText()) === "Overview");
  await page.locator('.nav-link:has-text("Assets")').focus();
  await page.keyboard.press("Enter");
  await sleep(400);
  check("a nav link works from the keyboard and moves aria-current", (await hash()).startsWith("#/assets") &&
    (await page.locator('.nav-link[aria-current="page"]').innerText()) === "Assets", await hash());
  await page.locator('.nav-link:has-text("Scans")').click();
  await sleep(300);
  check("clicking another destination navigates", (await hash()).startsWith("#/scans"), await hash());
  await page.goBack();
  check("the back button returns to the previous page", (await hash()).startsWith("#/assets"), await hash());
  await page.goBack();
  check("and again", (await hash()).startsWith("#/overview"), await hash());
  check("a screen's title follows the page", /Overview · Cerberus/.test(await page.title()));

  // ------------------------------------------------------------------ overview
  await page.waitForSelector(".kpi");
  await axe("overview");
  const kpi = await page.locator(".kpi").evaluateAll((els) => els.map((e) => ({
    title: e.querySelector("h2").textContent, value: e.querySelector(".kpi-value").textContent })));
  check("four KPI cards with the lab data",
    JSON.stringify(kpi.map((k) => [k.title, k.value])) === JSON.stringify([["Active findings", "136"], ["Actively exploited", "5"], ["Confirmed", "1"], ["Assets", "2"]]),
    JSON.stringify(kpi));
  check("the KPI qualifier carries the critical count", /5 critical/.test(await page.locator(".kpi").first().innerText()));

  const cards = page.locator(".risk-card");
  check("Top risks shows six cards", (await cards.count()) === 6, String(await cards.count()));
  const scores = await cards.locator(".risk").evaluateAll((els) => els.map((e) => parseFloat(e.textContent)));
  check("Top risks are ordered by score, highest first", scores.length === 6 && scores.every((v, i) => i === 0 || scores[i - 1] >= v), scores.join(","));
  check("each card has a name that says what it opens", /^CVE-\d{4}-\d+ on .+, risk score \d+\.\d/.test(await cards.first().getAttribute("aria-label")), await cards.first().getAttribute("aria-label"));

  const sums = await page.locator(".bars").evaluateAll((lists) => lists.map((ul) =>
    [...ul.querySelectorAll("li")].reduce((n, li) => n + parseInt(li.querySelector(".bar-value").textContent.replace(/,/g, ""), 10), 0)));
  check("both breakdown charts add up to the 136 active findings", sums.length === 2 && sums.every((n) => n === 136), sums.join(","));
  const chartTitles = await page.locator(".chart-title").allTextContents();
  check("chart titles state the finding, not the topic", /7 of 136 active findings are high or critical/.test(chartTitles[0]) && /1 of 136 are confirmed/.test(chartTitles[1]), chartTitles.join(" | "));
  check("the chart's bars are decoration; the numbers are text", (await page.locator(".bar-track[aria-hidden='true']").count()) === 6);

  const scanRow = await page.locator("#recent-scans-title >> xpath=ancestor::section//tbody/tr").first().innerText();
  check("Recent scans lists the lab scan", /127\.0\.0\.1/.test(scanRow) && /completed/i.test(scanRow), scanRow.replace(/\s+/g, " "));
  await page.screenshot({ path: `${SP}/e2e-0-overview.png`, fullPage: true });

  // a KPI link lands on the matching filter
  await page.locator('.kpi:has(h2:has-text("Actively exploited")) a').click();
  await page.waitForSelector('h1:has-text("Findings")');
  await page.waitForSelector(".pagination p");
  await sleep(500);
  check("the Actively exploited card opens findings filtered to KEV", /kev=1/.test(await hash()) && /of 5 findings/.test(await page.locator(".pagination p").innerText()), await hash());
  await page.goBack();
  await page.waitForSelector(".risk-card");

  // a Top risks card opens that finding
  await page.locator(".risk-card").first().click();
  await page.waitForSelector("#finding-detail h2");
  check("a Top risks card opens the finding's detail", /finding=/.test(await hash()) && (await page.locator("#finding-detail h2").innerText()).startsWith("CVE-"), await hash());
  await page.goBack();

  await go("findings", "Findings");
  // ------------------------------------------------------------------ findings: list
  await page.waitForSelector("tbody tr");
  await sleep(300);
  await axe("findings");
  check("default view is active findings only", /of 136 findings/.test(await page.locator(".pagination p").innerText()));
  check("25 rows per page", (await page.locator("tbody tr").count()) === 25);
  check("table has a caption and scoped headers", (await page.locator("caption").count()) === 1 && (await page.locator('th[scope="col"]').count()) >= 6);
  await page.screenshot({ path: `${SP}/e2e-1-findings.png` });

  // sorting is exposed as aria-sort and lives in the URL
  await page.click('button.th-sort:has-text("CVSS")');
  await sleep(500);
  check("sorting by CVSS updates the URL", /sort=cvss_score/.test(await hash()), await hash());
  check("sorted header reports aria-sort", (await page.locator('th[aria-sort="descending"]').count()) === 1);
  await page.click('button.th-sort:has-text("CVSS")');
  await sleep(400);
  check("clicking again reverses to ascending", (await page.locator('th[aria-sort="ascending"]').count()) === 1);
  await page.click('button.th-sort:has-text("Risk")');
  await sleep(400);

  // pagination
  await page.click('button:has-text("Next")');
  await sleep(500);
  check("Next moves to page 2 in the URL", /page=2/.test(await hash()), await hash());
  check("range text is correct", /Showing 26–50 of 136/.test(await page.locator(".pagination p").innerText()), await page.locator(".pagination p").innerText());
  await page.click('button:has-text("Previous")');
  await sleep(400);

  // search: debounced, and in the URL
  await page.fill('input[type="search"]', "42013");
  await sleep(900);
  check("search is reflected in the URL", /q=42013/.test(await hash()), await hash());
  const cves = await page.locator("tbody .row-button").allTextContents();
  check("search filters to matching CVEs", cves.length > 0 && cves.every((c) => c.includes("2021-42013")), `${cves.length} rows`);
  await page.click('button:has-text("Clear filters")');
  await sleep(600);
  check("Clear filters resets the URL", (await hash()) === "#/findings", await hash());

  // filters
  await page.selectOption("select >> nth=1", "active_detection");
  await sleep(600);
  check("Confirmed-only filter leaves the one probe-confirmed finding", /of 1 findings/.test(await page.locator(".pagination p").innerText()), await page.locator(".pagination p").innerText());
  await page.click('button:has-text("Clear filters")');
  await sleep(500);

  // ------------------------------------------------------------------ findings: keyboard + detail
  const first = page.locator("tbody .row-button").first();
  await first.focus();
  await page.keyboard.press("Enter");
  await page.waitForSelector("#finding-detail h2");
  await sleep(300);
  check("opening a finding from the keyboard works", (await page.locator("#finding-detail").count()) === 1);
  check("focus moves into the detail panel", await page.evaluate(() => document.activeElement && document.activeElement.tagName === "H2"),
    await page.evaluate(() => document.activeElement && document.activeElement.tagName));
  check("the row button reports it expanded", (await first.getAttribute("aria-expanded")) === "true");
  await axe("findings with detail panel");
  await page.screenshot({ path: `${SP}/e2e-2-detail.png` });
  await page.keyboard.press("Escape");
  await sleep(400);
  check("Escape closes the panel", (await page.locator("#finding-detail").count()) === 0);
  check("focus returns to the row that opened it", await page.evaluate(() => document.activeElement && document.activeElement.classList.contains("row-button")));

  // ------------------------------------------------------------------ criticality edit, end to end
  // Drive the level DOWN then UP so the test passes on any starting state (it is idempotent),
  // and so both directions of re-ranking are checked.
  const confirmed = () => page.locator("tbody tr", { has: page.locator(".badge", { hasText: "Confirmed" }) }).first();
  const score = async () => parseFloat((await confirmed().locator(".risk").first().innerText()).match(/[0-9.]+/)[0]);
  await confirmed().locator(".row-button").click();
  await page.waitForSelector("#finding-detail h2");

  const setLevel = async (level, reason) => {
    await page.click('#finding-detail button:has-text("Change")');
    await page.selectOption("#finding-detail select >> nth=0", level);
    await page.fill('#finding-detail input[placeholder*="checkout"]', reason);
    await page.click('#finding-detail button:has-text("Save and re-rank")');
    await page.waitForSelector('#finding-detail [role="status"] .banner', { timeout: 8000 });
    await sleep(800);
  };

  await setLevel("low", "throwaway test box");
  const low = await score();
  await setLevel("critical", "customer-facing lab host");
  const high = await score();
  check("lowering then raising criticality moves the score both ways", high > low, `${low} -> ${high}`);
  check("saving criticality confirms it", /re-ranked/.test(await page.locator('#finding-detail [role="status"]').innerText()));
  const critText = await page.locator("#finding-detail section").innerText();
  check("a person's decision is labelled 'set by you', not 'inferred'", /set by you/.test(critText) && !/inferred from hostname/.test(critText), critText.replace(/\s+/g, " "));
  const why = await page.locator("#finding-detail .reasoning-text").first().innerText();
  check("the explanation cites the criticality reason you gave", /customer-facing lab host/.test(why), why.slice(0, 110));

  // ------------------------------------------------------------------ assets
  await go("assets", "Assets");
  await page.waitForSelector("tbody tr");
  await axe("assets");
  const assetText = await page.locator("tbody").innerText();
  check("assets show the manual criticality as set by you", /set by you/.test(assetText) && /critical/i.test(assetText));
  check("assets still show inferred ones as inferred", /inferred from hostname/.test(assetText));
  await page.screenshot({ path: `${SP}/e2e-3-assets.png` });
  await page.locator('tbody a:has-text("findings for")').first().click();
  await page.waitForSelector("tbody tr");
  await sleep(400);
  check("an asset's finding count links to its findings", /asset=/.test(await hash()) && (await page.locator(".legend[role='status']").count()) === 1, await hash());
  check("that view is narrowed to one asset", (await page.locator("tbody tr td.mono").allTextContents()).every((t, _, all) => t === all[0]) );

  // ------------------------------------------------------------------ evidence
  await go("evidence?target=127.0.0.1:18081", "Evidence");
  await page.waitForSelector("tbody tr");
  await axe("evidence");
  const targets = await page.locator("tbody tr td.mono.nowrap").allTextContents();
  check("evidence can be narrowed to one asset", targets.length >= 2 && targets.every((t) => t === "127.0.0.1:18081"), targets.join(","));
  const tools = (await page.locator("tbody .row-button").allTextContents()).join(" ");
  check("evidence names the tools that saw it", /nmap/.test(tools) && /nuclei/.test(tools) && /tcp_connect/.test(tools), tools);
  await page.locator("tbody .row-button", { hasText: "nuclei" }).click();
  await sleep(200);
  check("a raw observation expands from the keyboard-operable button", (await page.locator("pre").count()) === 1);
  await page.screenshot({ path: `${SP}/e2e-4-evidence.png` });

  // ------------------------------------------------------------------ shell and profile
  await go("overview", "Overview");
  check("the brand in the sidebar is not a link",
    (await page.locator(".sidebar .brand a").count()) === 0);
  check("there is no Landing page option in the dashboard",
    (await page.locator('a:has-text("Landing page")').count()) === 0);
  check("a minimal profile component lives in the bottom-left sidebar",
    (await page.locator(".sidebar-footer .account-link").count()) === 1);
  await page.locator(".account-link").click();
  await page.waitForSelector('h1:has-text("Profile")');
  check("the account link opens the Profile page", (await hash()).startsWith("#/profile"), await hash());
  const profile = await page.locator("main").innerText();
  check("Profile shows the name, email and how the person signed in",
    profile.includes(NAME) && profile.includes(EMAIL) && /Signed in with Email and password/.test(profile));
  check("Profile is honest that there is no Google photo for this sign-in (initials, not a broken image)",
    (await page.locator(".profile-card img").count()) === 0 && /initials/i.test(await page.locator(".profile-card .avatar").getAttribute("aria-label")));
  check("Profile lists connected deployment accounts, empty here", /Nothing connected/.test(profile));
  await axe("profile");
  await page.screenshot({ path: `${SP}/e2e-3b-profile.png` });

  // ------------------------------------------------------------------ domains
  await go("domains", "Targets");
  await page.waitForSelector('form[aria-label="Add a custom domain"]');
  await page.waitForSelector("text=No targets yet");
  check("a new account has no targets", (await page.locator("article").count()) === 0 && /No targets yet/.test(await page.locator("main").innerText()));
  await axe("targets (empty)");

  // The Deployment path, on a server with no OAuth apps: every provider says so, and nothing can be started.
  await page.getByLabel(/Deployment/).check();
  await page.waitForSelector("text=Add a deployment");
  await page.waitForSelector("article");
  const providerCards = await page.locator("article").allInnerTexts();
  const providerCard = (name) => providerCards.find((c) => c.includes(name)) || "";
  check("the three providers are listed", providerCards.length === 3 && ["Vercel", "Netlify", "Cloudflare"].every((n) => providerCard(n)));
  check("Netlify and Cloudflare say they are not set up and offer nothing to click",
    ["Netlify", "Cloudflare"].every((n) => /Not set up on this server/.test(providerCard(n)) && !/Connect|access token/i.test(providerCard(n).replace(/Not set up on this server/, ""))));
  check("Vercel, with no OAuth app but an encryption key, offers an access token and no OAuth Connect",
    /Use an access token/.test(providerCard("Vercel")) && !/Connect Vercel/.test(providerCard("Vercel")) && !/Not set up/.test(providerCard("Vercel")));
  // the token form: opens, explains the trade-off, never shows the value, and refuses garbage locally
  await page.getByRole("button", { name: "Use an access token" }).click();
  await page.waitForSelector('input[name="access-token"]');
  const tokenForm = await page.locator(".token-form").innerText();
  check("the token form says where to make the token and warns that Vercel tokens are not read-only",
    /Account Settings/.test(tokenForm) && /no read-only token/i.test(tokenForm));
  check("the token field is a password field with no autofill", (await page.locator('input[name="access-token"]').getAttribute("type")) === "password" && (await page.locator('input[name="access-token"]').getAttribute("autocomplete")) === "off");
  await axe("targets (access token form open)");
  await page.fill('input[name="access-token"]', "not a token");
  await page.getByRole("button", { name: "Connect with token" }).click();
  await page.waitForSelector(".token-form [role='alert']");
  const tokenError = await page.locator(".token-form [role='alert']").innerText();
  check("a value that is not shaped like a token is refused, without repeating it", /does not look like an access token/.test(tokenError) && !tokenError.includes("not a token"), tokenError);
  check("nothing was connected by that", (await page.locator("article:has-text('Vercel') .connection").count()) === 0);
  await page.getByRole("button", { name: "Hide access token form" }).click();
  const deployText = (await page.locator("main").innerText()).replace(/\s+/g, " ");
  check("the page explains that only platform addresses can be verified this way, and a custom domain still needs DNS",
    /\*\.vercel\.app/.test(deployText) && /custom domain still needs a DNS record/.test(deployText));
  await axe("targets (deployment, unconfigured)");
  await page.getByLabel(/Custom domain/).check();

  await page.fill('input[placeholder="example.com"]', "https://not-a-bare-domain.com/path");
  await page.click('button:has-text("Add domain")');
  await page.waitForSelector('[role="alert"]');
  check("a URL is refused with what to enter instead", /bare domain/i.test(await page.locator('[role="alert"]').innerText()));
  problems.length = 0; // the 400 above was the point of that step

  await page.fill('input[placeholder="example.com"]', DOMAIN.toUpperCase());
  await page.click('button:has-text("Add domain")');
  await page.waitForSelector("article");
  const card = page.locator("article").first();
  check("the domain is added, normalised, and not yet verified", (await card.locator("h3").innerText()) === DOMAIN && /Not verified yet/.test(await card.innerText()));
  const cardText = await card.innerText();
  check("it shows the exact DNS record to publish", cardText.includes(`_cerberus-challenge.${DOMAIN}`) && /cerberus-verify=\S{20,}/.test(cardText) && /\bTXT\b/.test(cardText));
  check("each value can be copied by a labelled button",
    (await card.locator("button", { hasText: "Copy" }).count()) === 2 &&
    /record name for/.test(await card.locator("button", { hasText: "Copy" }).first().innerHTML()));
  await axe("targets (pending)");

  await card.locator('button:has-text("Check verification")').click();
  await page.waitForSelector("article [role='status'] .banner");
  const verdict = await card.locator("[role='status']").innerText();
  check("an unpublished record is a plain answer, not an error", /_cerberus-challenge|DNS could not be reached|try again/i.test(verdict) && /Not verified yet/.test(await card.innerText()), verdict);
  await page.screenshot({ path: `${SP}/e2e-5-domains.png` });

  // A test cannot publish DNS, so this is the one place the harness reaches around the UI: mark the
  // domain verified directly (what a successful check does), then confirm the UI reflects it.
  py("-c", [
    "from sqlalchemy import select",
    "from core.db import session_scope",
    "from core.models import Domain, utcnow",
    "with session_scope() as s:",
    `    d = s.scalar(select(Domain).where(Domain.domain == '${DOMAIN}'))`,
    "    d.verification_status = 'verified'; d.verified_at = utcnow()",
  ].join("\n"));
  await page.reload({ waitUntil: "networkidle" });
  await page.waitForSelector("article");
  check("a verified domain says so and offers to scan it", /Verified/.test(await page.locator("article").first().innerText()) && (await page.locator('article a:has-text("Scan this domain")').count()) === 1);
  await axe("targets (verified)");
  await page.locator('article a:has-text("Scan this domain")').click();
  await page.waitForSelector('h1:has-text("Scans")');
  check("Scan this domain opens Scans with that domain chosen", /domain=/.test(await hash()) && (await page.locator("select").first().inputValue()) !== "" && (await page.locator("select option:checked").first().innerText()) === DOMAIN);

  // ------------------------------------------------------------------ scans
  await page.waitForSelector("tbody tr");
  await axe("scans");
  const start = page.locator('button:has-text("Start scan")');
  check("there is no 'I am authorised' checkbox: the verified domain is the proof", (await page.locator('label:has-text("I own this target")').count()) === 0);
  check("a verified domain and the Safe profile are enough to start", !(await start.isDisabled()));
  await page.locator('input[type="radio"][value="thorough"]').check();
  check("choosing Thorough demands explicit acceptance", await start.isDisabled());
  await page.locator('label:has-text("I understand this profile") input').check();
  check("accepting Thorough re-enables Start", !(await start.isDisabled()));
  await page.locator('input[type="radio"][value="safe"]').check();
  check("switching back to Safe clears the acceptance", (await page.locator('label:has-text("I understand this profile")').count()) === 0);
  // A scan that started this instant must read as "just now" -- not hours ago. The database stores UTC
  // without a zone, and a browser in India used to read that as local time, 5.5 hours off.
  py("-c", [
    "from sqlalchemy import select",
    "from core.db import get_default_tenant, session_scope",
    "from core.models import Scan, User, utcnow",
    "with session_scope() as s:",
    `    u = s.scalar(select(User).where(User.email == '${EMAIL}'))`,
    "    s.add(Scan(tenant_id=get_default_tenant(s).id, user_id=u.id, target_domain='fresh.example.com',",
    "               status='completed', started_at=utcnow(), completed_at=utcnow()))",
  ].join("\n"));
  await page.reload({ waitUntil: "networkidle" });
  await page.waitForSelector("tbody tr");
  const freshRow = page.locator("tbody tr", { hasText: "fresh.example.com" });
  const freshText = await freshRow.innerText();
  check("a scan started just now reads as just now, in India's timezone", /just now|1 min ago/.test(freshText) && !/\bh ago\b/.test(freshText), freshText.replace(/\s+/g, " "));
  check("its tooltip gives the exact time in IST", /IST$/.test((await freshRow.locator("td[title]").first().getAttribute("title")) || ""));
  const historyRow = await page.locator("tbody tr", { hasText: "127.0.0.1" }).first().innerText();
  check("history lists the real scan with its evidence count", /127\.0\.0\.1/.test(historyRow) && /completed/i.test(historyRow) && /\b5\b/.test(historyRow), historyRow.replace(/\s+/g, " "));
  await page.locator("tbody tr", { hasText: "127.0.0.1" }).locator(".row-button").click();
  await sleep(200);
  check("expanding a scan reports no problems when there were none", /No problems were reported/.test(await page.locator("tbody").innerText()));
  await page.screenshot({ path: `${SP}/e2e-6-scans.png` });

  // ------------------------------------------------------------------ signing out, and another account
  await page.locator('button:has-text("Sign out")').click();
  await page.waitForSelector('h2:has-text("Sign in")');
  check("signing out returns to the sign-in form", (await page.locator(".nav").count()) === 0);
  await page.reload({ waitUntil: "networkidle" });
  await page.waitForSelector('h2:has-text("Sign in")');
  check("a reload after signing out stays signed out (the cookie is gone)", (await page.locator(".account-link").count()) === 0);
  check("the refresh cookie was removed", !(await ctx.cookies()).some((c) => c.name === "cerberus_refresh" && c.value));

  const again = await ctx.request.post(`${API}/api/v1/auth/login`, { data: { email: EMAIL.toUpperCase(), password: PASSWORD } });
  check("signing back in works (and email case does not matter)", again.ok());
  await page.evaluate(() => localStorage.setItem("cerberus.hadSession", "1"));
  await page.reload({ waitUntil: "networkidle" }); // a hash-only navigation would not re-run the session restore
  await go("overview", "Overview");
  await page.waitForSelector(".kpi");
  check("...and the dashboard picks that session up", (await page.locator(".account-link").innerText()).includes(NAME));

  const other = await browser.newContext({ viewport: { width: 1360, height: 900 } });
  await other.addInitScript(() => localStorage.setItem("cerberus.hadSession", "1"));
  const second = await other.request.post(`${API}/api/v1/auth/register`, { data: { email: `second-${RUN}@example.com`, password: PASSWORD } });
  check("a second account is created", second.status() === 201);
  const op = await other.newPage();
  await op.goto(`${WEB}/platform/`, { waitUntil: "networkidle" });
  await op.waitForSelector(".nav-link");
  await op.goto(`${WEB}/platform/#/domains`, { waitUntil: "networkidle" });
  await op.waitForSelector('h1:has-text("Targets")');
  await sleep(500);
  check("a second account cannot see the first one's targets", !(await op.locator("main").innerText()).includes(DOMAIN));
  await op.goto(`${WEB}/platform/#/findings`, { waitUntil: "networkidle" });
  await op.waitForSelector('h1:has-text("Findings")');
  await sleep(500);
  check("...or its findings", /No findings yet/.test(await op.locator("main").innerText()));
  await op.goto(`${WEB}/platform/#/scans`, { waitUntil: "networkidle" });
  await op.waitForSelector('h1:has-text("Scans")');
  await sleep(500);
  check("...and with no verified domain it is told to verify one first", /Verify a domain first/.test(await op.locator("main").innerText()) && (await op.locator('button:has-text("Start scan")').count()) === 0);
  await other.close();

  // ------------------------------------------------------------------ reflow
  await go("findings", "Findings");
  await page.waitForSelector("tbody tr");
  for (const [w, label] of [[680, "200% zoom"], [390, "phone"]]) {
    await page.setViewportSize({ width: w, height: 900 });
    await sleep(300);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
    check(`no page-level horizontal scroll at ${label} (${w}px)`, !overflow);
    await page.screenshot({ path: `${SP}/e2e-${w}.png` });
  }
  await page.setViewportSize({ width: 390, height: 900 });
  const nav = await page.locator(".nav-link").evaluateAll((els) => els.map((e) => { const r = e.getBoundingClientRect(); return r.left >= 0 && r.right <= window.innerWidth && r.height >= 44; }));
  check("on a phone all six destinations fit the width and are 44px tall", nav.length === 6 && nav.every(Boolean), nav.join(","));
  const scroller = await page.evaluate(() => { const w = document.querySelector(".table-wrap"); return w.scrollWidth > w.clientWidth && w.tabIndex === 0; });
  check("on a phone the table scrolls inside a focusable region", scroller);

  check("no console or page errors", problems.length === 0, problems.slice(0, 3).join(" | "));
  await browser.close();
  const failed = results.filter((r) => !r).length;
  console.log(`\n${results.length - failed}/${results.length} checks passed`);
  process.exit(failed ? 1 : 0);
})();
