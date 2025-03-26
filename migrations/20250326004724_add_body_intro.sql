ALTER TABLE posts ADD COLUMN intro_limit_opt int
    CHECK (intro_limit_opt >= 300 AND intro_limit_opt <= 2000);
