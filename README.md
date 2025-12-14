# Phishing Email Tracking System

**CS437/SEC537 - Part 3**

A Python-based web application that tracks interactions with phishing emails (opens and clicks) while distinguishing between automated security scanners (bots) and real human interactions.

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Usage](#usage)
4. [API Endpoints](#api-endpoints)
5. [Detection Logic](#detection-logic)
6. [Code Structure](#code-structure)

---

## Overview

Email security gateways (Gmail, Outlook, corporate filters) automatically scan links and images in emails, creating false positives for tracking systems. This application implements sophisticated detection logic to distinguish between:

- **Provider Scan / Security Bot**: Automated scanners from email providers
- **Real Human Click**: Actual human interactions

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python server.py
```

The server starts at `http://localhost:8000`

## Usage

### 1. Generate Tracking URLs

```bash
curl "http://localhost:8000/generate?dest=https://example.com"
```

Response:
```json
{
  "tracking_id": "550e8400-e29b-41d4-a716-446655440000",
  "pixel_url": "http://localhost:8000/pixel/550e8400.../&t=1702234567",
  "click_url": "http://localhost:8000/click/550e8400.../&t=1702234567&dest=...",
  "destination": "https://example.com"
}
```

### 2. Embed in Email

**Tracking Pixel (for open detection):**
```html
<img src="http://yourserver/pixel/{id}?t={timestamp}" width="1" height="1" />
```

**Tracking Link (for click detection):**
```html
<a href="http://yourserver/click/{id}?t={timestamp}&dest={encoded_url}">Click here</a>
```

### 3. View Results

```bash
curl "http://localhost:8000/stats/{tracking_id}"
```

Or visit the interactive API docs at `http://localhost:8000/docs`

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/pixel/{id}?t={timestamp}` | GET | Tracking pixel - returns 1x1 transparent GIF |
| `/click/{id}?t={timestamp}&dest={url}` | GET | Click tracking - serves JS verification page |
| `/verify/{id}` | POST | JavaScript verification callback |
| `/generate?dest={url}` | GET | Generate new tracking URLs |
| `/stats/{id}` | GET | View all events for a tracking ID |
| `/docs` | GET | Interactive API documentation (Swagger UI) |

---

## Detection Logic

The system uses multiple heuristics to determine if a request is from a bot or human:

### Bot Indicators

| Indicator | Weight | Implementation |
|-----------|--------|----------------|
| **User-Agent Analysis** | High | Checks for known scanner patterns: `GoogleImageProxy`, `Microsoft Defender`, `Cisco IronPort`, `Barracuda`, `Proofpoint`, etc. |
| **Timing Analysis** | High | Access within 0-2 seconds of email delivery indicates automated scanning |
| **IP Reputation** | High | Checks if IP is from datacenter ranges (AWS, Azure, GCP, DigitalOcean, etc.) |
| **Request Method** | Medium | HEAD requests instead of GET indicate link scanners |
| **Rapid Access** | Medium | More than 3 accesses in 10 seconds suggests automated scanning |
| **No JavaScript** | High | Bots typically don't execute JavaScript |

### Human Indicators

| Indicator | Description |
|-----------|-------------|
| **Browser User-Agent** | Standard browser patterns: Chrome, Firefox, Safari, Edge |
| **Natural Timing** | Access delay > 5 seconds after email delivery |
| **Residential/Mobile IP** | Non-datacenter IP addresses |
| **Mouse Movement** | Real cursor activity detected via JavaScript |
| **Valid Fingerprint** | Complete browser fingerprint with screen size, timezone, language |

### Detection Functions

Located in `server.py`:

| Function | Line | Purpose |
|----------|------|---------|
| `analyze_request()` | ~470 | Main detection engine - combines all heuristics |
| `is_datacenter_ip_local()` | ~340 | Fast CIDR-based datacenter IP check |
| `check_ip_type()` | ~360 | IP reputation with ipinfo.io fallback |
| `get_recent_access_count()` | ~310 | Rapid access detection |

### Scoring System

```
bot_score = count(bot_indicators) + 2 * count(strong_bot_indicators)
human_score = count(human_indicators)

if bot_score > human_score:
    verdict = "BOT"
else:
    verdict = "HUMAN"
```

Strong bot indicators (double weight):
- Bot User-Agent pattern
- HEAD request
- Immediate access (< 2 seconds)
- Datacenter IP
- Rapid repeated access
- No JavaScript execution

---

## Code Structure

```
CS437 - HW2/
├── server.py                 # Main FastAPI application
│   ├── Configuration         # Database paths, constants
│   ├── Bot Detection         # UA patterns, datacenter CIDRs
│   ├── Database Functions    # SQLite operations
│   ├── IP Reputation         # CIDR check + ipinfo.io
│   ├── Detection Engine      # analyze_request()
│   ├── Tracking Endpoints    # /pixel, /click, /verify
│   └── Utility Endpoints     # /generate, /stats
│
├── templates/
│   └── verification.html     # JavaScript verification page
│       ├── Mouse Tracking    # Captures cursor movements
│       ├── Fingerprinting    # Collects browser data
│       └── AJAX Callback     # Sends data to /verify
│
├── requirements.txt          # Python dependencies
├── README.md                 # This documentation
│
├── data/                     # Auto-created
│   └── tracking.db           # SQLite database
│
└── logs/                     # Auto-created
    └── tracking.log          # JSON log file
```

### Key Components

#### 1. Tracking Pixel (`/pixel/{id}`)
- Serves 1x1 transparent GIF
- Cannot execute JavaScript
- Relies on User-Agent, timing, and IP analysis

#### 2. Click Tracking (`/click/{id}`)
- Serves HTML verification page instead of immediate redirect
- JavaScript collects:
  - Mouse movements (up to 20 events)
  - Browser fingerprint (screen, timezone, language, WebGL, canvas)
- Sends AJAX to `/verify/{id}` after 2-second delay
- Then redirects to destination

#### 3. Verification Callback (`/verify/{id}`)
- Receives JavaScript-collected data
- Makes final bot/human determination
- Logs complete event with all indicators

### Database Schema

```sql
CREATE TABLE tracking_events (
    id INTEGER PRIMARY KEY,
    tracking_id TEXT,
    event_type TEXT,        -- pixel_open, click_page_served, click_verified
    timestamp DATETIME,
    source_ip TEXT,
    user_agent TEXT,
    request_method TEXT,
    verdict TEXT,           -- BOT or HUMAN
    reason TEXT,            -- Explanation of verdict
    extra_data TEXT         -- JSON with fingerprint, mouse data
);
```

---

## Console Output Example

```
======================================================================
[2024-12-07T15:30:45] TRACKING EVENT
======================================================================
  Tracking ID   : 550e8400-e29b-41d4-a716-446655440000
  Event Type    : click_verified
  Source IP     : 203.0.113.45
  User-Agent    : Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120...
  Method        : POST
  >>> VERDICT   : [HUMAN]
  >>> Reason    : Standard browser User-Agent; Natural delay (45s); Mouse movement detected (8 events); Valid browser fingerprint
======================================================================
```

---

## Testing with ngrok

For testing with real email providers (Gmail, Outlook):

```bash
# Install ngrok: https://ngrok.com/download
ngrok http 8000

# Use the ngrok URL in your tracking links
# Example: https://abc123.ngrok.io/pixel/{id}?t={timestamp}
```

---

## Dependencies

- **fastapi** - Web framework
- **uvicorn** - ASGI server
- **jinja2** - Template rendering
- **httpx** - Async HTTP client (for ipinfo.io)
- **aiosqlite** - Async SQLite
- **python-multipart** - Form data handling
