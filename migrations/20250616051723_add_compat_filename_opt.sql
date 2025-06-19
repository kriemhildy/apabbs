ALTER TABLE posts ADD COLUMN compat_filename_opt text
    CHECK (length(compat_filename_opt) >= 5 AND length(compat_filename_opt) < 253);
