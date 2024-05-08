schizo.land
-----------

1. install postgresql version 15.
2. install rust using rustup.
3. install "pkg-config" via your package manager.
4. install sqlx-cli for postgres only:
   cargo install sqlx-cli --no-default-features --features native-tls,postgres
5. create a role with CREATEDB (or SUPERUSER) and LOGIN in postgresql.
6. add DATABASE_URL with postgres connection credentials to an ".env" file.
7. also set "DEV=1" in the .env file.
8. add a random IP_SALT (at least 16 chars) to the .env file.
9. run "sqlx database create" to create the database.
10. run "sqlx migrate run" to update the database schema to the current point.
11. configure a web server (e.g. nginx) to proxy to the app server.
    this is necessary for receiving assets (css and js). this server will also
    need to enable web socket upgrades and IP forwarding.
12. run "cargo run" to start the app server on port 7878. alternatively set a
    "PORT" env var to run on a different port.
13. access the app via "localhost" in a browser.
