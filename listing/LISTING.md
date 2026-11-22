# Cynthia — Marketplace listing assets

Everything the Developer Portal asks for at the listing step, prepared
in advance. Nothing here has been submitted anywhere.

## App name (public listing)

**Cynthia — Verified Answer AI**

Internal project name: "Cynthia for HighLevel". The public name drops
the HighLevel reference on purpose: HighLevel's White-Label listing
type (the one this app uses, for maximum reach across white-label
domains) requires that the app not reference HighLevel anywhere —
name, copy, or screenshots — and references cause disapproval at
review.

## Tagline

The verified-answer AI for your clients — she only says what the
business approved, verbatim.

## Description (listing body)

Cynthia, by Planet Leads — the verified-answer AI for your clients.
Cynthia answers customer questions only from facts the business
approves — verbatim — and says she doesn't know instead of inventing
prices or policies. White-label ready: sell her under your agency's
brand.

How it works:

- Install Cynthia into a client sub-account. She opens as a page
  inside the client's account — no separate app, no second screen.
- Out of the box she runs in demo mode on the Planet Leads demo fact
  store, so your team can see exactly how she answers — and how she
  honestly says "I don't know" when a fact isn't approved.
- When the client goes live, Planet Leads provisions that business's
  own Cynthia with the business's approved facts (hours, prices,
  policies, services). An admin pastes her endpoint into Cynthia's
  setup panel, and from then on she answers only from that business's
  facts.
- She never guesses, never paraphrases a price, and never invents a
  policy. Every verified answer is the business's own approved words.

## Listing configuration (mirrors the portal — see app-manifest.json)

| Field | Value |
|---|---|
| App type | Public (build/test as Private first, per HighLevel's docs) |
| Target user | Sub-account |
| Who can install | Both Agency & Sub-account |
| Bulk install | Yes (required for new apps) |
| Listing type | White-Label |
| Category | The portal's AI / chat category (confirm exact label in portal) |
| Company name | Planet Leads |
| Support email | planetleads1@gmail.com |
| Privacy policy | Draft in `privacy-policy.md` — host it and paste the URL |
| Terms of service | Draft in `terms.md` — host it and paste the URL |
| Logo | `assets/logo.png` (final, at listing); placeholder: `assets/logo.svg` |
| Preview images | Screenshots of the Custom Page (demo + live states) — capture at listing |

## Pricing plans (Subscription — maps to existing tiers, no new pricing)

HighLevel takes a 15% revenue share on Marketplace earnings; the
seller keeps 85%. Agencies can white-label and re-bill the app to
their sub-accounts at their own markup.

| Plan | Type | Unit | Price |
|---|---|---|---|
| Cynthia Starter | Subscription (monthly) | Per location (sub-account) | From Planet Leads' existing white-label Starter band: **$20–$100/mo per client**. Enter the contracted tier price in the portal at listing — this build creates no new price. |

Optional at listing: a free trial (HighLevel supports 1–90 days) —
the demo mode already lets agencies evaluate Cynthia free inside
their own account, so a trial is not required for evaluation.
