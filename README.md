Anonymous Pre-Approval Bulletin Board System (APABBS)
-----------------------------------------------------

The philosophy of this application is that it is better to moderate posts before they are
published. Bad actors are usually content to get their message heard even if it comes at the cost
of a ban. Reactive moderation also causes unnecessary stress for moderators, as they have to be
concerned about what has been posted at all hours of the day. There is also a time pressure on
moderators to act quickly and make a judgment on something that has already been published, whereas
it would be more comfortable to take their time with it in some cases.

Features
--------
- Developed in Rust, so very fast and memory-safe. This highly reduces the risk of memory leaks or
  buffer overflows (a major cause of security vulnerabilities), as well as generally reducing the
  likelihood of bugs.
- Has a small memory footprint and compiles quickly due to performing most CPU-intensive tasks via
  command-line tools.
- Asynchronous programming (via Tokio) massively reduces CPU downtime caused by I/O operations and
  background tasks, making the application more responsive for multiple users per CPU core.
- Built using the Axum web framework, a simple but highly capable library under active development.
- Supports any media format compatible with FFmpeg (pretty much everything). Less common video
  formats are converted to a web-compatible format that works in all major browsers (H.264 MP4 w/
  AAC).
- Generates highly optimized WebP thumbnail files of images for fast loading on list pages while
  still retaining the original files on individual post pages for fidelity.
- Supports a simple integration with YouTube that pulls video thumbnails.
- Uses standard human-readable CSS and JavaScript with no external front-end libraries.
- HTML markup is clear and neatly indented.
- WebSocket integration ensures that new posts show up immediately and update the page title so
  that it can be seen in another tab.
- Various browser quirks in Chromium, Firefox and Safari have been addressed.
- Designed to display well both on desktop and mobile.
- Every request aside for uploading files should be handled extremely quickly by the server. All
  time-consuming activities are offloaded to background processes.
- Designed to work perfectly without JavaScript, although JavaScript makes it better.
- Designed to work in both light and dark modes with dark mode as the default. This preference is
  automatically detected based on a user's operating system configuration.
- All web requests have integration tests built for them including some error cases. The tests run
  quickly.
- Screenshots of the home page are taken every hour by Chromium. These screenshots are included if
  the URL of the home page is posted in any embeddable place (X, Discord). Individual post pages
  also have embed support.
- Users who create accounts can configure a time zone for displaying timestamps in.
- Automatic flood detection prevents botlike behavior and auto-bans IP addresses for a month.
- Admins can add specific words or phrases as spam terms which temp ban IPs.
- Full error handling using standard Rust tools.
- Supports Sentry integration for monitoring errors.
- Full code commenting for use with rustdoc.
- Simple Bash-based tools for deployment and syncing development with production.
- Has both simple SQL migrations and more complicated Rust migrations to ensure earlier versions of
  the code can always be brought up to date.
- Code is organized into reasonable categories and file lengths.
- Has CSRF protection.

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
