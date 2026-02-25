-- Alter the intro_limit constraint to change the range from >= 96 and < 1600 to >= 0 and < 1200
ALTER TABLE posts DROP CONSTRAINT posts_intro_limit_opt_check;
ALTER TABLE posts ADD CONSTRAINT posts_intro_limit_check
    CHECK (intro_limit >= 0 AND intro_limit < 1600);
