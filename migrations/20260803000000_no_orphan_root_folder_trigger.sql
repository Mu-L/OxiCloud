-- ════════════════════════════════════════════════════════════════════════════
-- D0 / Step 8 — No-orphan-root-folder constraint trigger
-- ════════════════════════════════════════════════════════════════════════════
-- Closes the "every root folder must belong to a drive" invariant at the DB
-- level (docs/plan/drive.md §3 "DB-level invariant: no orphan root folder"
-- and §10 Phase A step 8).
--
-- The application-layer guarantee is the atomic four-write transaction in
-- DrivePgRepository::create_personal_drive_atomic — drive + root folder +
-- drives.root_folder_id wire-up + Owner role_grant, all-or-nothing. This
-- migration adds the DB-level belt for the suspenders: a CONSTRAINT TRIGGER
-- that refuses any `storage.folders` row with `parent_id IS NULL` unless
-- some drive's `root_folder_id` points back at it.
--
-- DEFERRABLE INITIALLY DEFERRED is mandatory because the atomic creation
-- order is folder-INSERTed → drive-UPDATEd → COMMIT; an immediate trigger
-- would fire after the folder INSERT (before the drive UPDATE) and refuse
-- the row even though the transaction would close cleanly. Deferred to
-- COMMIT, the check sees the wired state.
--
-- What this migration does NOT cover:
--   * The reverse direction — "drives.root_folder_id must point at a folder
--     whose parent_id IS NULL". A follow-up trigger on storage.drives can
--     close that seam; today the cascade FKs and the application invariant
--     keep it correct.
--   * DELETE handling — folder DELETE cascades to drive DELETE via the
--     drives.root_folder_id ON DELETE CASCADE FK from M1, so the
--     "deleting the root would leave the drive dangling" path is
--     structurally prevented.


-- ── Pre-flight: refuse if any existing orphan root folders are present ────
-- Same pattern as M2: scan current data, RAISE EXCEPTION on any violation
-- so the trigger doesn't land into an inconsistent dataset that would
-- silently break later as soon as one of those rows gets UPDATEd.
--
-- A row is an "orphan root folder" iff `parent_id IS NULL` and no drive's
-- `root_folder_id` equals its id. Trashed rows are exempt (they're soft-
-- deleted in place and the chroot resolver never lands on them).

DO $BODY$
DECLARE
    orphan_count BIGINT;
BEGIN
    SELECT count(*) INTO orphan_count
    FROM storage.folders f
    WHERE f.parent_id IS NULL
      AND NOT f.is_trashed
      AND NOT EXISTS (
          SELECT 1 FROM storage.drives d
           WHERE d.root_folder_id = f.id
      );

    IF orphan_count > 0 THEN
        RAISE EXCEPTION
            'D0 step-8 migration refused: % root folder(s) (parent_id IS NULL, '
            'not trashed) have no drive pointing at them via root_folder_id. '
            'These would silently fail the constraint trigger on their next '
            'UPDATE. Inspect with: SELECT f.id, f.user_id, f.drive_id, f.name '
            'FROM storage.folders f WHERE f.parent_id IS NULL AND NOT f.is_trashed '
            'AND NOT EXISTS (SELECT 1 FROM storage.drives d WHERE d.root_folder_id '
            '= f.id); — then either wire each row to a drive or trash it before '
            'retrying.',
            orphan_count;
    END IF;
END $BODY$;


-- ── 1. The check function ─────────────────────────────────────────────────
-- AFTER trigger so the row is already in the snapshot — the lookup against
-- storage.drives correctly sees the UPDATE that closed the cycle (when
-- called from the atomic transaction, that UPDATE happens later in the
-- same tx; the DEFERRED firing time waits for COMMIT so visibility is
-- correct).

CREATE OR REPLACE FUNCTION storage.check_no_orphan_root_folder()
RETURNS trigger AS $$
BEGIN
    -- The trigger fires for every INSERT/UPDATE on storage.folders. We
    -- only need to enforce the invariant on root rows; non-root folders
    -- are guaranteed correct by their parent_id FK.
    IF NEW.parent_id IS NOT NULL THEN
        RETURN NULL;
    END IF;

    -- Trashed root folders are soft-deleted in place — the resolver
    -- never lands on them, and they were valid roots before they got
    -- trashed. Skip enforcement; the row's history is preserved.
    IF NEW.is_trashed THEN
        RETURN NULL;
    END IF;

    -- The core check: some drive must be pointing at this row as its
    -- root_folder_id, AND that drive must be the same one carrying our
    -- drive_id (the 1:1 bidirectional invariant from §3).
    IF NOT EXISTS (
        SELECT 1 FROM storage.drives d
         WHERE d.id = NEW.drive_id
           AND d.root_folder_id = NEW.id
    ) THEN
        RAISE EXCEPTION
            'Orphan root folder rejected: storage.folders id=% has '
            'parent_id IS NULL and drive_id=%, but no drive has '
            'root_folder_id pointing at it. Root folders must be '
            'created via the atomic four-write transaction (see '
            'docs/plan/drive.md §3 and DrivePgRepository::'
            'create_personal_drive_atomic); direct SQL is not '
            'supported.',
            NEW.id, NEW.drive_id;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION storage.check_no_orphan_root_folder() IS
    'DB-level guard for the "every root folder belongs to a drive" '
    'invariant. Wired as a DEFERRABLE INITIALLY DEFERRED constraint '
    'trigger so the atomic create transaction (folder INSERTed before '
    'drive UPDATEd) commits cleanly. See docs/plan/drive.md §3.';


-- ── 2. The constraint trigger ─────────────────────────────────────────────
-- CONSTRAINT TRIGGER (vs regular trigger) is what lets us declare
-- DEFERRABLE INITIALLY DEFERRED. Without it the row-level fire happens
-- immediately after the INSERT and the atomic transaction can't possibly
-- have UPDATEd drives.root_folder_id yet — every legitimate create would
-- be rejected.
--
-- CONSTRAINT TRIGGERs don't support a WHEN clause; the parent_id /
-- is_trashed filtering lives inside the function above.

DROP TRIGGER IF EXISTS trg_no_orphan_root_folder ON storage.folders;
CREATE CONSTRAINT TRIGGER trg_no_orphan_root_folder
    AFTER INSERT OR UPDATE ON storage.folders
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION storage.check_no_orphan_root_folder();


-- ── 3. Post-flight: confirm the trigger landed ────────────────────────────
-- Belt-and-suspenders: PostgreSQL silently does nothing if CREATE TRIGGER
-- fails to attach (unlikely, but a cosmic-ray check). Refusing the
-- migration here surfaces the bug rather than letting it commit silently.

DO $BODY$
DECLARE
    trigger_exists BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM pg_trigger t
        JOIN pg_class c ON c.oid = t.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'storage'
           AND c.relname = 'folders'
           AND t.tgname  = 'trg_no_orphan_root_folder'
           AND NOT t.tgisinternal
    ) INTO trigger_exists;

    IF NOT trigger_exists THEN
        RAISE EXCEPTION
            'D0 step-8 migration post-flight failed: trigger '
            'trg_no_orphan_root_folder did not attach to storage.folders.';
    END IF;
END $BODY$;
