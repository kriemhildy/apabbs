ALTER TABLE posts ADD COLUMN compat_filename_opt text
    CHECK (length(compat_filename_opt) >= 8 AND length(compat_filename_opt) < 256);
