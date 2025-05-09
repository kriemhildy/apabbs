Anonymous Pre-Approval Bulletin Board System (APABBS)
-----------------------------------------------------

The general philosophy of this forum system is that moderation of posts after
they are published is a bad strategy. Trolls are usually content to get their
message heard even if it comes at the cost of their (temporary) ban.

Thus the only way to really allow anonymous conversation is to review every
single post prior to its publication. [Only this will ensure that the fullness
of the varied experience of the moderator will not go to waste.]

Installation
------------

1. install rust using rustup.
2. install postgresql, pkg-config, rsync, gnupg, libvips-tools, ffmpeg and chromium.
3. create a "gpg.key" file with a random string value.
4. install sqlx-cli for postgres only:
   cargo install sqlx-cli --no-default-features --features native-tls,postgres
5. create a role with CREATEDB, LOGIN and PASSWORD in postgresql.
6. copy .env.example to .env and set the variables as needed.
7. install direnv and run "direnv allow".
8. run "sqlx database setup" to create and migrate the database.
9. configure a web server (e.g. nginx) to proxy to the app server.
    this is necessary for serving assets (css, js, media). it is also
    necessary for SSL encryption via certbot. this server will need to enable
    web socket upgrades and X-Real-IP forwarding.
10. run "cargo run" to start the app server in debug mode.
11. access the app via "localhost" in a browser.
