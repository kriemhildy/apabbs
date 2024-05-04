schizo.land
-----------

1. install postgresql version 15.
2. install rust using rustup.
3. run "cargo build" to install cargo packages.
4. install "pkg-config" via your package manager.
5. install sqlx-cli for postgres only:
   cargo install sqlx-cli --no-default-features --features native-tls,postgres
6. create a role with createdb (or superuser) and login in postgresql.
7. add DATABASE_URL with postgres connection credentials to an ".env" file.
8. also set "DEV=1" in the .env file.
9. add a random IP_SALT (at least 16 chars) to the .env file.
10. run "sqlx database create" to create the database.
11. run "sqlx migrate run" to update the database schema to the current point.
12. configure a web server (e.g. nginx) to proxy to the app server.
    this is necessary for receiving assets (css and js).
13. run "cargo run" to start the app server on port 7878.
14. access the app via "localhost" in a browser.
