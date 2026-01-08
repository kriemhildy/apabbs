Anonymous Pre-Approval Bulletin Board System (APABBS)
-----------------------------------------------------

The philosophy of this application is that it is better to moderate posts before they are
published. Bad actors are usually content to get their message heard even if it comes at the cost
of their ban. Reactive moderation also causes unnecessary stress for moderators, as they have to be
concerned about what has been posted at all hours of the day. There is also a time pressure on
moderators to act quickly and make a judgment on something that has already been published, whereas
it would be more comfortable to take their time with it in some cases.

Installation
------------

1. Install Rust using `rustup`.
2. Install PostgreSQL, pkg-config, rsync, GnuPG, VIPS, FFmpeg and Chromium. On Debian:
   `apt install postgresql pkg-config rsync gnupg libvips-tools ffmpeg chromium`
3. Create a `gpg.key` file with a random string value: `gpg --gen-random 2 32 | base64 > gpg.key`
4. Install sqlx-cli for Postgres only:
   `cargo install sqlx-cli --no-default-features --features native-tls,postgres`
5. Create a Postgres role (user account) with CREATEDB, LOGIN and PASSWORD privileges:
   `CREATE ROLE apabbs WITH CREATEDB LOGIN PASSWORD 'your_password';`
6. Copy `.env.example` to `.env` and set the variables as appropriate.
7. Install direnv and run `direnv allow`: `apt install direnv && direnv allow`
8. Run `sqlx database setup` to create and migrate the database.
9. Configure a web server (e.g. NGINX) to proxy to the app server. This is necessary for serving
   assets (CSS, JavaScript, media files). It is also necessary for SSL encryption via Certbot. This
   server will need to enable WebSocket upgrades and X-Real-IP forwarding.
10. Run `cargo run` to start the app server in debug mode.
11. Access the app via `http://localhost` in a browser.
