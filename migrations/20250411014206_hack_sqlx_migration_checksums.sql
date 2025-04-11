-- similar to the prior hack, this one updates some checksums of old migrations,
-- and the new files will be committed after this migration is applied to all
-- of our active environments.
BEGIN;

UPDATE _sqlx_migrations SET checksum =
    '\x204551c48fd709c91b8732706e086fadb5730b67fdec1f287d279e1ae5b8301c830ab927df54a9d382efa3fcbc970fb4'
    WHERE version = 20240907014705 AND checksum !=
    '\x204551c48fd709c91b8732706e086fadb5730b67fdec1f287d279e1ae5b8301c830ab927df54a9d382efa3fcbc970fb4';

UPDATE _sqlx_migrations SET checksum =
    '\x24593181621f54941eeaf031fcce187ee76be15535e2651c5cf5d2f296b894d702db788d668530391786ebe82e5236d7'
    WHERE version = 20250212070204 AND checksum !=
    '\x24593181621f54941eeaf031fcce187ee76be15535e2651c5cf5d2f296b894d702db788d668530391786ebe82e5236d7';

COMMIT;
