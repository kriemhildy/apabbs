
-- Add 'pending' as the first value to the account_role enum
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_type WHERE typname = 'account_role'
    ) THEN
        -- Add 'pending' before 'novice' in the enum
        -- This requires recreating the enum type, as PostgreSQL does not support inserting before a value
        -- 1. Rename the existing type
        ALTER TYPE account_role RENAME TO account_role_old;

        -- 2. Create the new type with 'pending' as the first value
        CREATE TYPE account_role AS ENUM ('pending', 'novice', 'member', 'mod', 'admin');

        -- 3. Alter columns to use the new type
        ALTER TABLE accounts ALTER COLUMN role DROP DEFAULT;
        ALTER TABLE accounts ALTER COLUMN role TYPE account_role USING role::text::account_role;
        ALTER TABLE accounts ALTER COLUMN role SET DEFAULT 'pending'::account_role;

        -- 4. Drop the old type
        DROP TYPE account_role_old;
    END IF;
END$$;
