# Stripe Subscriber Role

A [RoleLogic](https://rolelogic.faizo.net) plugin that grants Discord roles
automatically based on a member's **Stripe** subscription or payment history —
active subscribers, specific plans, trials, big spenders, past-due win-backs,
and much more, with a rich AND/OR condition builder.

Built for Discord **bot developers who already bill through Stripe**: if your
checkout stamps the buyer's Discord ID into Stripe (RoleLogic's own billing
does, and so do most Discord-SaaS setups), this plugin links members
**automatically** — no email verification, no OAuth, nothing for members to do.

- **Tech:** Rust + Axum + PostgreSQL + SQLx (single small binary, ~30–50 MB RAM).
- **Mount path:** `/stripe-subscriber-role`  ·  **Default port:** `8096`.

---

## How linking works (the important part)

A Discord member is matched to their Stripe records by their **Discord user ID**,
read straight from Stripe — in this priority order:

1. `subscription.metadata.<key>` (default key: `discord_user_id`)
2. the subscription's customer `metadata.<key>`
3. a `checkout.session.completed`'s `client_reference_id`
4. an already-linked customer row

The default key `discord_user_id` matches **RoleLogic's own billing** exactly
([`api/src/common/stripe.service.ts`](../../rolelogic/api/src/common/stripe.service.ts)
sets `subscription_data.metadata.discord_user_id` **and** `client_reference_id`),
so connecting RoleLogic's Stripe account needs **zero changes** to your billing.

**Other bot developers:** make your checkout do one of these and you're done:

```ts
// Option A — subscription metadata (recommended)
stripe.checkout.sessions.create({
  mode: 'subscription',
  line_items: [{ price, quantity: 1 }],
  client_reference_id: discordUserId,                 // also captured
  subscription_data: { metadata: { discord_user_id: discordUserId } },
});
```

If you use a different metadata field name (e.g. `discordId`), set it as the
**Discord-ID metadata key** when you connect (the plugin also auto-tries
`discord_user_id`, `discord_id`, `discordId`, `discord`).

> No Discord ID in Stripe at all? Then this plugin can't link those customers —
> add the metadata above to your checkout and re-run a sync (it backfills on the
> 6-hour reconcile, or instantly via webhooks).

---

## Setup for a server admin

Everything is done from the plugin's config screen inside the RoleLogic
dashboard (the embedded rule-builder).

### 1. Create a restricted (read-only) Stripe key

In the Stripe Dashboard → **Developers → API keys → Create restricted key**.
Grant **Read** on:

| Resource | Why |
|---|---|
| Customers | who the customers are, email, country, delinquency |
| Subscriptions | status, plan, price, renewal, trial |
| Charges (Payment Intents) | lifetime spend / payment count *(optional)* |
| Products & Prices | the plan picker in the rule builder |
| Account *(optional)* | shows your business name instead of a generic label |

Copy the key — it starts with `rk_live_…` (or `rk_test_…`). **Never** paste a
full secret `sk_…` key if you can avoid it; restricted is safer.

### 2. Connect it in the rule builder

Open the role in RoleLogic → the plugin tab → **Connect Stripe** → paste the
key. The plugin validates it, stores it **AES-256-GCM encrypted** (key derived
from `SESSION_SECRET`), and starts importing your subscribers in the background.

### 3. (Recommended) Add a webhook for instant updates

The connect screen shows a per-account webhook URL like:

```
https://<your-domain>/stripe-subscriber-role/webhooks/stripe/<account_ref>
```

In Stripe → **Developers → Webhooks → Add endpoint**, point it at that URL and
subscribe these events:

```
checkout.session.completed
customer.subscription.created
customer.subscription.updated
customer.subscription.deleted
customer.updated
customer.deleted
charge.succeeded
invoice.payment_failed
```

Then paste the endpoint's **signing secret** (`whsec_…`) back into the plugin
(Connect another → same key + the secret). Signatures are verified on every
delivery. Without a webhook, roles still reconcile every 6 hours.

### 4. Pick who gets the role

Choose a preset (Active subscribers, a specific plan, trial users, annual
members, big spenders, past-due win-back, any customer) or build an **Advanced
rule** combining conditions with AND (within a group) and OR (across groups).
**Preview** shows the live match count before you **Save**.

---

## Conditions

Rules are a DNF tree: the role is granted if a member matches **any** group, and
within a group **all** conditions must hold.

**Subscription**
`has_active_subscription` · `subscription_status` (active/trialing/past_due/…)
· `is_trialing` · `is_past_due` · `cancels_at_period_end`
· `active_subscription_count` · `subscribed_to_product` (pick by name)
· `subscribed_to_price` (pick by name) · `plan_amount` ($) · `billing_interval`
(day/week/month/year) · `subscription_age_days` · `days_until_renewal`
· `total_mrr` ($, normalized monthly)

**Customer**
`is_customer` · `customer_age_days` · `is_delinquent` · `lifetime_spend` ($)
· `successful_payments` · `country_code` · `currency` · `email_domain`

Operators per type: booleans use equals; numbers use `=, ≠, >, ≥, <, ≤, between`;
strings use `=, ≠, contains, regex, is one of, is not one of`; product/price sets
use `equals (includes), is one of, is not one of`. Money conditions are entered
in dollars in the UI and compared in the currency's smallest unit.

---

## How it works

```
Stripe ──(webhook: per-account, signature-verified)──▶ webhook ingestor
   │                                                        │
   └──(6h reconcile / on-connect backfill: list API)────────┤  upsert raw
                                                            ▼
                       stripe_customers + stripe_subscriptions  (mirror)
                                                            │ recompute
                                                            ▼
                              stripe_member_facts  (one row per member, denormalized)
                                                            │ evaluate (SQL push-down)
                                                            ▼
                       qualifying Discord IDs ──▶ RoleLogic User-Management API
```

- **Member facts** are denormalized so a rule compiles to a plain `WHERE` clause
  (e.g. `has_active_subscription AND $1 = ANY(product_ids)`); the same DNF is
  evaluated in Rust for single-member webhook updates.
- **Guild membership** comes only from the centralized Auth Gateway
  (`/auth/internal/*`); the plugin keeps no Discord tables.
- **Durable job queue** (Postgres `FOR UPDATE SKIP LOCKED` + `LISTEN/NOTIFY`)
  drives player/config/account syncs and the initial backfill, with retry +
  backoff + a dead-letter status.

---

## Deployment

1. Pick the path prefix `/stripe-subscriber-role` and port `8096` (already wired
   in `main.rs` / `compose.yml` / `Dockerfile`).
2. Set env (`.env.example` documents everything):
   - `BASE_URL=https://<domain>/stripe-subscriber-role` (HTTPS, no trailing slash)
   - `SESSION_SECRET` and `INTERNAL_API_KEY` — **must match the Auth Gateway's**
   - `DATABASE_URL`, `POSTGRES_PASSWORD`
   - optional `AUTH_GATEWAY_URL`, `RL_DASHBOARD_ORIGIN`, `ROLELOGIC_API_URL`
   - There is **no global Stripe key** — each server connects its own.
3. Add a Cloudflare Tunnel ingress rule: `^/stripe-subscriber-role` → `localhost:8096`.
4. The slug is already registered in `Auth-Gateway/src/plugins.rs::PLUGINS`.
5. Register the plugin URL `https://<domain>/stripe-subscriber-role` in the
   RoleLogic dashboard.

```bash
docker compose up -d --build         # app + tuned Postgres, ~128–512 MB
# or run migrations standalone first:
#   <binary> migrate
```

`GET /stripe-subscriber-role/health` returns liveness (DB) + Stripe reachability.

---

## Security

- Restricted Stripe keys and webhook secrets are **encrypted at rest**
  (AES-256-GCM, KEK = HKDF(`SESSION_SECRET`)). A DB dump alone can't read them.
- Webhooks are authenticated by **Stripe signature** (HMAC-SHA256, 5-min replay
  window) using each account's own signing secret; the account ref in the URL is
  not a secret.
- Admin writes require Discord **Manage Server** (cookie path, Origin-checked) or
  a RoleLogic-minted iframe-session token bound to `(guild, role)`.
- Per-IP rate limiting, default-deny security headers, graceful drain on SIGTERM.
