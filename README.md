# Chat Masala Imageboard

Chat Masala is a small imageboard project built for discussions for the Indian community, and for learning full-stack web development. It is currently intended for local/private use, not public production hosting.

## What It Does

- Public boards and threads
- Thread replies with optional images
- Anonymous names and tripcodes
- CAPTCHA verification
- Sensitive image marking
- Thread catalog view
- Watched threads and local “my posts”
- Quote links and quote previews
- Image gallery inside threads
- Geo flag display on `/pol/`
- Staff moderation panel
- Admin, moderator, and janitor roles
- Reports, bans, board-specific bans, ban requests, deleted posts, and moderation logs

## Tech Stack

- Node.js
- Express
- SQLite
- Plain HTML/CSS/JavaScript
- Multer for image uploads
- geoip-lite for IP country lookup

## How To Run Locally

Install dependencies:

```bash npm install


server.js              Main Express server and API routes
database.js            SQLite schema and migrations
public/index.html      Front page
public/board.html      Board page
public/thread.html     Thread/reply page
public/mod.html        Moderation panel
public/catalog.html    Catalog view
public/image.html      Image viewer
public/rules.html      Rules page
public/style.css       Shared styling
geo-overrides.json     Manual GeoIP corrections



Moderation Features
The moderation panel supports:
Viewing recent posts
Deleting posts or images
Marking images sensitive
Reports
Ban requests
Global bans
Board-specific bans
Deleted post review
Staff accounts
Board-specific janitor permissions
Moderation logs
Current Limitations
This project is still experimental and not production-ready.
Known limitations:
SQLite is simple but not ideal for a large public site
IP geolocation can be inaccurate, especially with VPNs
Uploaded files and database files are local
No email system
No production deployment setup
No automated test suite yet
Security should be reviewed before any public use



Feedback Wanted
I would appreciate feedback on:
Code organization
Security issues
Moderation system design
Database structure
Whether the API routes are clean and understandable
What should be improved before public hosting
What features are overcomplicated or unnecessary
How to make the project easier to maintain
