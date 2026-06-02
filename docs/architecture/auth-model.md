# Authentication Model

OxiCloud's authentication is built on a single principle: **email is the identity, everything else is optional**. A user account is uniquely identified by their email address. Username, password, and OIDC linkage are each independent, optional slots — none of them is required, and none of them is the source of identity. Which slots a user has determines which login paths are available to them.

This page is the canonical reference for the identity and authentication surface. For the magic-link mechanism in detail (token lifecycle, invitation flow, kill switches), see [Magic-link external authentication](/architecture/magic-link-auth). For how grants are evaluated, see [ReBAC Authorization](/architecture/rebac-authorization).

## Identity model

Every user row in `auth.users` carries one identity field and three independent credential slots.

| Slot | Type | Required | Meaning |
|---|---|---|---|
| `email` | `String UNIQUE NOT NULL` | yes | The identity. Every login path ultimately resolves here. |
| `username` | `String UNIQUE NULL` | no | Optional handle. 2-64 chars, `[A-Za-z0-9._-]+`, **no `@`**. Multiple NULLs coexist under the UNIQUE index. |
| `password_hash` | `String NULL` | no | Argon2 hash if the user chose one. NULL = no password. No sentinel strings. |
| `oidc_subject` | `String NULL` | no | IdP subject claim if the user linked an external identity. NULL = no OIDC. |
| `is_external` | `bool` | yes (default false) | Provisioning origin marker. `true` = created via email-invitation. Affects home-folder provisioning and DAV access. |

The **`@` ban on usernames** is what makes the username and email namespaces provably disjoint. The login dispatcher relies on this — input containing `@` is unambiguously an email lookup, input without is a username lookup. No fallback chain, single DB hit.

Eligibility predicates derive from the slots:

```rust
fn has_password(&self) -> bool      { self.password_hash.is_some() }
fn has_oidc(&self) -> bool          { self.oidc_subject.is_some() }
fn has_login_credential(&self) -> bool {
    self.has_password() || self.has_oidc()
}
```

## Login dispatcher

`POST /api/auth/login` accepts one identifier field that holds **either** a username or an email. The server dispatches in one branch:

```
input contains '@' → lookup by email,    verify password
input does not     → lookup by username, verify password
```

The `@` ban on usernames makes this unambiguous. A single DB lookup, no fallback chain, no cross-column scan.

The frontend's "Username or email" field submits whatever the user typed; the JSON field is still named `username` for backwards compatibility, with a docstring noting the dual semantics.

## Login paths

| Path | How it works | When available |
|---|---|---|
| **Username + password** | Type a handle and a password. Backend looks up by username, verifies the Argon2 hash. | User has both `username` and `password_hash` set. |
| **Email + password** | Type an email and a password. Backend looks up by email, verifies the hash. | User has `password_hash` set (username optional). |
| **Email + magic-link** | Type an email, click "Send sign-in link", receive a magic-link in the inbox, click it. | Magic-link eligibility (below). |
| **OIDC redirect** | Click "Sign in with {IdP}", redirect to IdP, return to OxiCloud authenticated. | User has `oidc_subject` set OR JIT-provisioning is enabled. |

### Magic-link eligibility

```
1. has_oidc()        → reject "oidc_user"   (unconditional)
2. has_password()    → reject "has_password" by default
                       allow when OXICLOUD_MAGIC_LINK_OPEN_TO_PASSWORD_USERS=true
3. neither           → allow
```

| User state | Magic-link eligible? |
|---|---|
| No password, no OIDC (typical external / fresh email-only signup) | Yes — always |
| Has password, no OIDC | Default no; flag flips to yes for lenient mode |
| Has OIDC (with or without password) | **No — always.** Flag has no effect. |

**OIDC is excluded unconditionally** because the IdP is the security boundary and may enforce MFA (TOTP, WebAuthn, conditional access, etc.) that a magic-link would bypass. Even when the operator wants lenient magic-link for password users, OIDC-linked accounts must stay on the IdP path.

## Registration paths

| Path | Pre-condition | What happens |
|---|---|---|
| `POST /api/auth/register` with `{email, password}` | Public registration enabled | User row created with both slots; classic path. |
| `POST /api/auth/register` with `{email}` only | Public registration enabled + SMTP configured | User row created with `password_hash = NULL`; welcome magic-link mailed. |
| `POST /api/grants` with `{ subject: { type: "email", email: "..." } }` | Sharer has Share permission | Recipient lazily provisioned as external; invitation magic-link mailed. |
| OIDC JIT | First IdP-mediated login + auto-provisioning enabled | User row created with `oidc_subject` set, no password. |

Anti-enumeration applies to the public `register` endpoint — see below.

## Anti-enumeration

The endpoint responses are tuned per attacker model:

| Endpoint | Response shape | Why |
|---|---|---|
| `POST /api/auth/register` (SMTP wired) | Uniform 200 on success **and** collision: `{"message": "Registration request received."}` | Per-user oracle on `email` / `username` would let an attacker probe account existence. The "check your email" cover story is honest because successful email-only signups receive a welcome mail. |
| `POST /api/auth/register` (SMTP not wired) | `201 + UserDto` on success, `409` on collision (classic) | Without the email cover story, a uniform response is misleading UX with no security benefit. |
| `POST /api/auth/magic-link/send` | Uniform 200 regardless of outcome | The mailbox owner is the only one who'd see whether mail arrived. |
| `POST /api/auth/login` | Uniform `403 "Invalid credentials"` | Same shape for unknown user / bad password / deactivated account. |

In all four cases the real reason is recorded in the `audit` channel — operators see the truth; attackers see the same response.

**Instance-wide policy stays visible** in every flow. `OXICLOUD_ENABLE_REGISTRATION=false`, OIDC-only mode, and SMTP-not-configured for email-only signup all return clear errors (403 / 503) — these are not per-user oracles, so hiding them would just frustrate legitimate users.

## Security trade-offs

| Concern | Current treatment |
|---|---|
| **Mailbox compromise = account compromise (lenient mode)** | When `OXICLOUD_MAGIC_LINK_OPEN_TO_PASSWORD_USERS=true`, a user's mailbox is as strong as their password — flip the password by mail. Operator opt-in only; off by default. Aligns with modern SaaS norms (Slack, Notion, Substack). |
| **Mailbox compromise = account compromise (strict mode)** | Only applies to magic-link-eligible users (no other credential). Their mailbox **is** their credential by design. Password-secured accounts are unaffected. |
| **No native MFA** | Today OIDC delegation is the only path to MFA — the IdP (Keycloak, Authentik, Okta) enforces TOTP/WebAuthn/etc., OxiCloud sees only the resulting ID token. This is why OIDC users are unconditionally excluded from magic-link. Native TOTP / WebAuthn enrolment is a future feature. |
| **Magic-link as bearer token** | A URL in an inbox is a bearer credential. PR 22 (planned) binds login-via-email tokens to the requesting browser via a challenge cookie. Invitations stay cross-device by necessity. |
| **Enumeration via timing** | Best-effort. `register` collision is the same code path as success (uniform response, similar latency); `magic-link/send` is bounded by per-target-email and per-IP rate limits. |

## Rate limits

Three caps protect the magic-link surface, two protect classic auth:

| Cap | Keyed on | Default | Env |
|---|---|---|---|
| Login attempts | client IP | 360/hour (test env) — production should tighten | `OXICLOUD_RATE_LIMIT_LOGIN_MAX` |
| Register attempts | client IP | 360/hour (test env) | `OXICLOUD_RATE_LIMIT_REGISTER_MAX` |
| Email-invite per sharer | `caller_id` | 50/hour | `OXICLOUD_MAGIC_LINK_INVITE_PER_CALLER_PER_HOUR` |
| Magic-link send per target email | normalised email | 5/hour | `OXICLOUD_MAGIC_LINK_SEND_PER_EMAIL_PER_HOUR` |
| Magic-link send per IP | client IP | 200/hour | `OXICLOUD_MAGIC_LINK_SEND_PER_IP_PER_HOUR` |

The two `magic-link/send` caps are **silently absorbed** when exceeded (uniform 200, no mail dispatched). The other caps surface 429 to the authenticated caller.

## Audit events

Every meaningful denial / suppression / outcome emits a structured event on the `audit` tracing target. Reason keys are stable — log aggregators key off them.

| Event | Reasons (subset) | Where it fires |
|---|---|---|
| `auth.login` | `created` | success path, `register` service |
| `auth.login_rejected` | `unknown_user`, `bad_password`, `account_deactivated` | `login` |
| `auth.register` | `created`, `email_taken`, `username_taken` | `register` service |
| `auth.magic_link_send` | `sent`, `no_account`, `oidc_user`, `has_password`, `account_deactivated`, `malformed_email`, `rate_limited_ip`, `rate_limited_email` | `send_login_link` + handler |
| `magic_link.invitation_suppressed` | `oidc_user`, `has_password` | `issue_invitation` |
| `magic_link.redemption_rejected` | `token_not_found`, `token_used`, `token_expired`, `account_deactivated` | `redeem` |
| `auth.app_password_create_rejected` | `external_user`, `no_username` | `create_app_password` |
| `authz.external_user_blocked` | `internal_only_surface` | `require_internal_user_layer` (CalDAV/CardDAV/WebDAV) |
| `auth.nc_basic_rejected` | `external_user` | `basic_auth_middleware` |
| `groups.search_rejected` | `external_user` | `search_groups` |
| `user_profile.rejected` | `external_no_relationship`, `target_external_hidden`, `target_hidden` | `get_user_profile` |
| `authz.denied` | resource-specific | `AuthorizationEngine::require` |

## Migration path for existing instances

The auth model lands across PR 16-20. The schema migration in PR 16 is forward-only and non-destructive:

- `username` and `password_hash` drop their `NOT NULL` constraints; existing rows keep their values.
- Email-shaped usernames on `is_external = true` users are NULL'd (they were redundant duplicates of the email column).
- Sentinel password strings (`__EXTERNAL_NO_PASSWORD__`, `__OIDC_NO_PASSWORD__`) are replaced with `NULL`.
- A CHECK constraint bans `@` in usernames going forward. Existing usernames are pre-validated as compliant.

Existing internal users with `username` + `password_hash` continue to work unchanged. External users keep their session UUIDs; their JWTs reference `user_id`, not `username`, so session continuity is preserved. The address-book and share-modal use the `username → given_name family_name → email` fallback chain for display.

## Future direction — per-user `login_strategy`

The current model is implicit: a user's available login paths derive from which credential slots they have set. A future direction is to make this **explicit** with a per-user policy enum:

| Strategy | Login requires |
|---|---|
| `passwordless` | magic-link only (current external default) |
| `password` | password only |
| `password_or_magic_link` | either (today's lenient mode, account-scoped instead of instance-scoped) |
| `password_and_magic_link` | both — true 2FA, mailbox-as-second-factor |
| `oidc` | IdP redirect (existing) |
| `password_and_totp` | once native TOTP enrolment ships |
| `password_and_webauthn` | once native WebAuthn enrolment ships |

`password_and_magic_link` is particularly interesting: it turns the parallel single-factor paths we have today into a real MFA primitive (something you know + access to a mailbox). No new auth code required — just a policy gate.

This stays out of the current PR sequence; the data model already accommodates it (the eligibility predicate is the single migration point).

## What is deliberately out of scope

- **Native TOTP / WebAuthn enrolment.** The eligibility predicate has room for a `Reject("mfa_enrolled")` branch once native MFA lands. OIDC delegation is the only MFA path today.
- **External-user → internal-user promotion.** When an external user later sets a credential, today `is_external` stays true (they remain second-class for home folders, DAV, etc.). A future PR promotes them properly.
- **Session-kind discriminator.** A magic-link session is indistinguishable from a password session today. Scoped sessions (Option-B style: "magic-link sessions only access granted resources") are deferred.
- **Differentiated session TTL for externals.** Refresh-token expiry is uniform today. Future env: `OXICLOUD_EXTERNAL_REFRESH_TOKEN_EXPIRY_DAYS`.
- **Open Cloud Mesh (OCM) federation.** A third source for external provisioning. The `ExternalIdentityLifecycleHook::on_user_created` design accommodates the `source` discriminator (`magic_link` / `oidc` / `ocm`).
- **Email-verified policy gates.** PR 23 (planned) introduces an `email_verified_at` column stamped on magic-link redemption + OIDC-with-verified-claim. Later policy PRs will let operators gate features (uploads, shares) on the signal.
- **Device-bound login tokens.** PR 22 (planned) adds a challenge cookie so login-via-email magic-links only redeem on the originating browser, closing the mailbox-as-bearer-token attack class. Invitations stay cross-device.
- **Anti-enumeration latency parity.** The success and collision branches of `register` already use similar code paths, but a sophisticated attacker could still time-distinguish. Deferred; rate-limiting bounds the damage.
- **Per-user opt-out of magic-link.** The `OPEN_TO_PASSWORD_USERS` flag is instance-wide today. A future per-account toggle for high-privilege users (admins, etc.) would need a column + extra eligibility branch.
- **`login_strategy` enum** (above) — the data model accommodates it but the policy code is future work.

## Related documents

- [Magic-link external authentication](/architecture/magic-link-auth) — the magic-link mechanism in depth: token lifecycle, invitation flow, kill switches, defence-in-depth boundary protections.
- [ReBAC Authorization](/architecture/rebac-authorization) — how grants are evaluated against `auth.users` rows (including externals).
- [Share Integration](/architecture/share-integration) — how share-link flow relates to the email-invite flow.
- [Environment Variables](/config/env) — the full set of `OXICLOUD_*` knobs referenced in this page.
