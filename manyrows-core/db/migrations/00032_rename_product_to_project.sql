-- +goose Up
-- Finish the Product -> Project rename at the database layer. Application code,
-- admin API routes, and the UI are renamed in the same change; this migration
-- brings the schema into line and preserves all existing data (pure renames,
-- no table rewrite).
--
-- The rename is performed dynamically rather than as a fixed list of ALTERs
-- because earlier partial work left the schema in a mixed state: some
-- constraint names were already renamed to "project_*" in 00001 while the
-- table, columns, and other objects still said "product". Only touching objects
-- whose names still contain "product" makes this pass correct on both a freshly
-- built database and an older deployment built from the original migrations.
-- +goose StatementBegin
DO $$
DECLARE
    r   record;
    sch text := current_schema();
BEGIN
    -- 1. The products table itself -> projects.
    IF EXISTS (
        SELECT 1 FROM pg_tables WHERE schemaname = sch AND tablename = 'products'
    ) THEN
        EXECUTE 'ALTER TABLE products RENAME TO projects';
    END IF;

    -- 2. Every product_id column (apps, roles, permissions, config_keys,
    --    config_values, feature_flags, feature_flag_overrides, webhooks, and
    --    the schema_* tables) -> project_id.
    FOR r IN
        SELECT table_name
        FROM information_schema.columns
        WHERE table_schema = sch AND column_name = 'product_id'
        ORDER BY table_name
    LOOP
        EXECUTE format('ALTER TABLE %I RENAME COLUMN product_id TO project_id', r.table_name);
    END LOOP;

    -- 3. Constraints whose name still contains "product" (apps_product_type_unique,
    --    config_keys_product_key_unique, and on an older deployment any
    --    *_product_id_fkey / products_pkey). Renaming a unique/PK constraint also
    --    renames its backing index, so process constraints before plain indexes.
    FOR r IN
        SELECT con.conname, rel.relname
        FROM pg_constraint con
        JOIN pg_class     rel ON rel.oid = con.conrelid
        JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
        WHERE nsp.nspname = sch AND con.conname LIKE '%product%'
    LOOP
        EXECUTE format('ALTER TABLE %I RENAME CONSTRAINT %I TO %I',
                       r.relname, r.conname, replace(r.conname, 'product', 'project'));
    END LOOP;

    -- 4. Remaining plain indexes whose name still contains "product"
    --    (idx_products_*, idx_*_product*).
    FOR r IN
        SELECT indexname
        FROM pg_indexes
        WHERE schemaname = sch AND indexname LIKE '%product%'
    LOOP
        EXECUTE format('ALTER INDEX %I RENAME TO %I',
                       r.indexname, replace(r.indexname, 'product', 'project'));
    END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
-- Reverse to a consistent "product_*" naming. This normalises the schema rather
-- than reconstructing the exact pre-rename mixed state.
-- +goose StatementBegin
DO $$
DECLARE
    r   record;
    sch text := current_schema();
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_tables WHERE schemaname = sch AND tablename = 'projects'
    ) THEN
        EXECUTE 'ALTER TABLE projects RENAME TO products';
    END IF;

    FOR r IN
        SELECT table_name
        FROM information_schema.columns
        WHERE table_schema = sch AND column_name = 'project_id'
        ORDER BY table_name
    LOOP
        EXECUTE format('ALTER TABLE %I RENAME COLUMN project_id TO product_id', r.table_name);
    END LOOP;

    FOR r IN
        SELECT con.conname, rel.relname
        FROM pg_constraint con
        JOIN pg_class     rel ON rel.oid = con.conrelid
        JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
        WHERE nsp.nspname = sch AND con.conname LIKE '%project%'
    LOOP
        EXECUTE format('ALTER TABLE %I RENAME CONSTRAINT %I TO %I',
                       r.relname, r.conname, replace(r.conname, 'project', 'product'));
    END LOOP;

    FOR r IN
        SELECT indexname
        FROM pg_indexes
        WHERE schemaname = sch AND indexname LIKE '%project%'
    LOOP
        EXECUTE format('ALTER INDEX %I RENAME TO %I',
                       r.indexname, replace(r.indexname, 'project', 'product'));
    END LOOP;
END $$;
-- +goose StatementEnd