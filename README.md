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

### 1. Install Node.js

Make sure Node.js is installed on your computer.

You can check by running:

```bash
node -v
```

If Node.js is installed, this will show a version number.


2. Install Project Dependencies
In the project folder, run:
npm install

This installs the packages the project needs.

3. Start The Server
Run:
node server.js


4. Open The Site
Open this in your browser:

example: http://localhost:3000


The imageboard should now be running locally.

# Main Files

server.js	
Main Express server and API routes

database.js	
SQLite schema and migrations

public/index.html	
Front page

public/board.html	
Board page

public/thread.html	
Thread/reply page

public/mod.html	
Moderation panel

public/catalog.html	
Catalog view

public/image.html	
Image viewer

public/rules.html	
Rules page

public/style.css	
Shared styling

geo-overrides.json	
Manual GeoIP corrections

# Moderation Features:
The moderation panel supports:
Viewing recent posts
Deleting posts or images
Marking images as sensitive
Reviewing reports
Reviewing ban requests
Creating global bans
Creating board-specific bans
Reviewing deleted posts
Managing staff accounts
Assigning janitors to specific boards
Viewing moderation logs

# Current Limitations:
This project is still experimental and not production-ready.
Known limitations:
SQLite is simple, but not ideal for a large public site.
IP geolocation can be inaccurate, especially with VPNs.
Uploaded files and database files are stored locally.
There is no email system.
There is no production deployment setup.
There is no automated test suite yet.
Security should be reviewed before any public use.
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
