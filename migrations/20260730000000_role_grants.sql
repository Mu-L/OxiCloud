-- ════════════════════════════════════════════════════════════════════════════
-- D-Prep: storage.role_grants — role-bundle replacement for access_grants
-- ════════════════════════════════════════════════════════════════════════════
-- Refactor #1 of the Drive sequence (see `docs/plan/drive.md` § Prerequisite).
--
-- Today every role assignment is stored as N rows in `storage.access_grants`
-- (one row per Permission in the role's bundle — editor = 4 rows, owner = 6).
-- This migration introduces `storage.role_grants` where each role assignment
-- is ONE row carrying the role name; permission expansion happens at engine
-- read time via the in-code `role_bundle()` function.
--
-- The five roles shipped on day one:
--   viewer       = {read}
--   commenter    = {comment, read}                                   ← new
--   contributor  = {create, read}                                    ← new
--   editor       = {comment, create, read, update}
--   owner        = {comment, create, delete, read, share, update}
--                  (post-Drive: + manage, when Group-as-Resource lands)
--
-- This migration is **additive**: `storage.access_grants` stays populated as
-- a dual-write safety net until a follow-up cleanup PR drops it after the
-- new model has baked in production. The down migration just drops
-- role_grants — access_grants is untouched, so rollback is trivial.
--
-- Pre-flight: the migration REFUSES to run if `access_grants` contains any
-- non-bundle clusters (permission sets that don't match one of the five
-- roles above). Run `tools/audit-grants-bundle-shape.sql` first to confirm
-- the data is clean — Ed's audit on 2026-06-17 returned 100% bundle-shaped.


-- ── 1. Pre-flight assertion ─────────────────────────────────────────────────
-- Refuse to migrate if there are any non-bundle clusters. The five known
-- bundles are listed here verbatim; keep them in sync with the in-code
-- `role_bundle()` function.

DO $BODY$
DECLARE
    bad_count BIGINT;
BEGIN
    WITH cluster AS (
        SELECT subject_type, subject_id, resource_type, resource_id,
               array_agg(permission ORDER BY permission) AS perms
        FROM storage.access_grants
        GROUP BY 1, 2, 3, 4
    )
    SELECT count(*) INTO bad_count
    FROM cluster
    WHERE perms NOT IN (
        ARRAY['read']::text[],
        ARRAY['comment','read']::text[],
        ARRAY['create','read']::text[],
        ARRAY['comment','create','read','update']::text[],
        ARRAY['comment','create','delete','read','share','update']::text[]
    );

    IF bad_count > 0 THEN
        RAISE EXCEPTION
            'D-Prep migration refused: % (subject,resource) clusters in '
            'storage.access_grants have non-bundle permission sets. Run '
            'tools/audit-grants-bundle-shape.sql section 3 to inspect them, '
            'then either resolve manually or extend the bundle list above '
            'with a new named role before retrying.', bad_count;
    END IF;
END $BODY$;


-- ── 2. The role_grants table ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS storage.role_grants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Subject (who has the role)
    --   'user'     → auth.users.id
    --   'group'    → storage.subject_groups.id
    --   'token'    → storage.shares.id (anonymous link — always 'viewer')
    subject_type    TEXT NOT NULL
        CHECK (subject_type IN ('user', 'group', 'token')),
    subject_id      UUID NOT NULL,

    -- Resource (what the role is on)
    -- 'drive' and 'group' join later as Drive + Group-as-Resource land.
    resource_type   TEXT NOT NULL
        CHECK (resource_type IN ('folder', 'file')),
    resource_id     UUID NOT NULL,

    -- Role — expands to a permission bundle via the in-code `role_bundle()`
    -- function. The CHECK lists the day-one role roster; adding a new
    -- role is a single ALTER TABLE DROP CONSTRAINT / ADD CONSTRAINT pair
    -- (or replace with a foreign key into a lookup table if instance-
    -- defined roles ever land).
    --
    -- Universal roster: ANY role can be granted on ANY resource_type.
    -- Permission bundles include capabilities the resource type may not
    -- check for (e.g. `Manage` on a folder, `Create` on a file); those
    -- produce harmless no-ops at engine read time — no per-resource-type
    -- validation needed at the DB layer.
    --
    -- The UI exposes only Viewer/Editor/Owner in the share dialog today
    -- (matches the existing 3-button UX). Commenter and Contributor stay
    -- in the enum for server-side use + future UI exposure when a real
    -- use case asks for them.
    role            TEXT NOT NULL
        CHECK (role IN ('viewer', 'commenter', 'contributor', 'editor', 'owner')),

    -- Audit + lifecycle
    granted_by      UUID NOT NULL,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,

    -- Exactly one role per (subject, resource). Atomic role changes become
    -- a single UPDATE; no DELETE+INSERT race.
    UNIQUE (subject_type, subject_id, resource_type, resource_id)
);

COMMENT ON TABLE  storage.role_grants IS
    'Role-based ReBAC grants. One row = one role assignment. Permission '
    'bundle expansion is in-code; see role_bundle() in '
    'src/application/dtos/grant_dto.rs. Replaces storage.access_grants; '
    'both tables coexist during the D-Prep dual-write window.';
COMMENT ON COLUMN storage.role_grants.role IS
    'One of viewer / commenter / contributor / editor / owner. Expanded to '
    'a Permission bundle by the in-code role_bundle() function at engine '
    'read time.';


-- ── 3. Indexes — match the hot-path queries ─────────────────────────────────

-- "What does this caller have access to?" — every WebDAV / NC request,
-- every UI default-drive resolution (post-Drive) hits this.
CREATE INDEX IF NOT EXISTS idx_role_grants_subject
    ON storage.role_grants (subject_type, subject_id);

-- "Who has access to this resource?" — share dialogs, audit views.
CREATE INDEX IF NOT EXISTS idx_role_grants_resource
    ON storage.role_grants (resource_type, resource_id);

-- Partial index on expiry — only rows that actually expire (mirrors the
-- access_grants index pattern, same rationale).
CREATE INDEX IF NOT EXISTS idx_role_grants_expires_at
    ON storage.role_grants (expires_at) WHERE expires_at IS NOT NULL;

-- For GET /api/grants/outgoing/resources (who granted what).
CREATE INDEX IF NOT EXISTS idx_role_grants_granted_by
    ON storage.role_grants (granted_by);


-- ── 4. Backfill from access_grants ─────────────────────────────────────────
-- For each (subject, resource) cluster in access_grants, write one
-- role_grants row with the matching role. The CASE expression mirrors
-- `Role::expand()` exactly — when that function changes (new role added),
-- update both this CASE and the CHECK constraint above.
--
-- expires_at: take MIN across the cluster (most conservative — the role
-- assignment expires at the earliest expiry of any of its constituent
-- grants). granted_at: MIN (when the role assignment started). granted_by:
-- the granter of the earliest row (preserves attribution to the admin who
-- initially set the role up).

WITH cluster AS (
    SELECT subject_type,
           subject_id,
           resource_type,
           resource_id,
           array_agg(permission ORDER BY permission) AS perms,
           MIN(granted_at)                           AS earliest_granted_at,
           MIN(expires_at)                           AS earliest_expires_at
    FROM storage.access_grants
    GROUP BY 1, 2, 3, 4
),
earliest_grantor AS (
    SELECT DISTINCT ON (subject_type, subject_id, resource_type, resource_id)
           subject_type,
           subject_id,
           resource_type,
           resource_id,
           granted_by
    FROM storage.access_grants
    ORDER BY subject_type, subject_id, resource_type, resource_id, granted_at ASC
)
INSERT INTO storage.role_grants
    (subject_type, subject_id, resource_type, resource_id,
     role, granted_by, granted_at, expires_at)
SELECT
    c.subject_type,
    c.subject_id,
    c.resource_type,
    c.resource_id,
    CASE c.perms
        WHEN ARRAY['read']::text[]
            THEN 'viewer'
        WHEN ARRAY['comment','read']::text[]
            THEN 'commenter'
        WHEN ARRAY['create','read']::text[]
            THEN 'contributor'
        WHEN ARRAY['comment','create','read','update']::text[]
            THEN 'editor'
        WHEN ARRAY['comment','create','delete','read','share','update']::text[]
            THEN 'owner'
    END                                             AS role,
    eg.granted_by,
    c.earliest_granted_at,
    c.earliest_expires_at
FROM cluster c
JOIN earliest_grantor eg USING (subject_type, subject_id, resource_type, resource_id)
ON CONFLICT (subject_type, subject_id, resource_type, resource_id) DO NOTHING;


-- ── 5. Post-flight consistency check ───────────────────────────────────────
-- Assert that the backfill landed one role_grants row per (subject,
-- resource) cluster in access_grants. Any mismatch means a bundle pattern
-- silently failed to match — refuses to commit, surfacing the bug.

DO $BODY$
DECLARE
    expected_clusters BIGINT;
    actual_role_grants BIGINT;
    null_roles BIGINT;
BEGIN
    SELECT count(*) INTO expected_clusters
    FROM (
        SELECT 1 FROM storage.access_grants
        GROUP BY subject_type, subject_id, resource_type, resource_id
    ) c;

    SELECT count(*) INTO actual_role_grants FROM storage.role_grants;

    IF expected_clusters != actual_role_grants THEN
        RAISE EXCEPTION
            'D-Prep backfill consistency check failed: expected % role_grants '
            'rows (one per distinct (subject, resource) cluster in access_grants), '
            'got %. Investigate before declaring the migration successful.',
            expected_clusters, actual_role_grants;
    END IF;

    -- Defensive: NULL role would mean the CASE expression failed to match.
    -- Pre-flight already refuses this, but double-check.
    SELECT count(*) INTO null_roles FROM storage.role_grants WHERE role IS NULL;
    IF null_roles > 0 THEN
        RAISE EXCEPTION
            'D-Prep backfill produced % role_grants rows with NULL role — '
            'a bundle pattern slipped past the pre-flight check. Investigate.',
            null_roles;
    END IF;
END $BODY$;
