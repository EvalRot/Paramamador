# Paramamador

Burp Suite extension for finding parameter names and URL endpoints.
It collects data from proxy traffic and JavaScript files, saves results to JSON, and shows them in a handy UI tab.

## Key Features

- Collect parameters and endpoints from requests/responses in Proxy and Repeater.
- Find endpoints in JavaScript by regex.
- Optional AST scan of JS with [`jsluice`](https://github.com/BishopFox/jsluice).
- Build a command to run [`httpx`](https://github.com/projectdiscovery/httpx) and “spray” selected endpoints across site tree paths.
- Send any found endpoint to Burp Repeater for manual testing.
- Auto-save results to JSON in your project folder.

## Requirements

- Java 21 (JDK 21)
- Gradle (wrapper included)
- Burp Suite (Community or Professional)
- Optional tools:
  - [`jsluice`](https://github.com/BishopFox/jsluice) (AST scan of JS)
  - [`httpx`](https://github.com/projectdiscovery/httpx) (endpoint spraying)
  - Optional: `GOPATH/bin` location so the extension can find these tools

## Install and Build

### Build with Gradle

```bash
./gradlew clean build
./gradlew jar
```

The JAR is created in `build/libs/`.

### Load in Burp

1) Burp → Extensions → Installed → Add → select the JAR from `build/libs/`.

Tip: Ctrl/⌘ + click the “Loaded” checkbox to quickly reload.

## First Run

On first start, the extension asks for:

### Project name
- Used as a base for result file names.

### Export directory
- Default: `HOME_DIR/.paramamador + DateTime`.
- Project-specific folder for all results.

### Global export directory
- Default: `HOME_DIR/.paramamador`.
- Global settings shared between projects.

### Load previous results from export directory
- If checked, the extension loads existing `.json` results on startup.

### Enable AST scanning with jsluice
- If checked, the extension enables scanning JS via `jsluice`.

### Go bin directory (optional)
- Path to `$GOPATH/bin` where `httpx` and `jsluice` may be installed.

## Usage

### Results
- The extension saves found parameter names and endpoints to JSON files in the export directory.
- The UI tab shows current data for quick work (copy, filter, send to tools).

### Settings Tab
- Scope only (default: true)
  - If on, only in-scope requests and JS files are scanned.
- Auto-save interval (default: 300 sec)
  - How often results are saved to JSON.
- maxInlineJsKb (default: 200 KB)
  - JS larger than this goes to a background queue for parallel scanning.
- maxQueueSize (default: 200)
  - Max size of the background queue for large JS files.
- Ignored patterns
  - JS sources containing these strings are skipped.
  - Default: `jquery`, `bootstrap`, `google-analytics`, `gtag.js`, `gpt.js`, `segment`.
- Path variable defaults
  - Your default values for variables in paths.
  - Example: found `/api/users/:userId`, you set `:userId = 1337`.
  - Then sending to httpx or Repeater will replace `:userId` with `1337`.
- Default request headers
  - Headers added by default in the Repeater send dialog.
  - Good for app-required headers so you don’t type them each time.

### Parameters Tab
- Name: parameter name.
- Sources: JS file or request where it was found.
- Types: where it was found (query/body/multipart/json); `js_ast` means from jsluice.
- Examples: sample values from traffic.
- Count: how many times it was seen.
- OnlyInCode: true if found by JS scanning (regex or jsluice).

### Endpoints Tab
- Endpoint: found URL endpoint.
- Source: JS file where it was found.
- Type: ABSOLUTE / RELATIVE / TEMPLATE / CONCAT.
- Referer: Referer value of the request that fetched the JS (helps identify target app when using a CDN).

#### Right-Click Actions
- Mark as False Positive
  - Marks this endpoint as false positive (by key: JS source + endpoint).
  - It won’t appear again in the main table (still stored in JSON with a flag).
- Run httpx (spray endpoints)
  - Build a list of Absolute URLs by combining selected endpoints with site tree paths for the target host (from Referer).
  - Example:
    - Selected endpoints: `/a/b`, `/c/d`
    - Site tree has: `example.com/api/v1`, `example.com/home`
    - The tool generates:
      - `example.com/api/v1/a/b`
      - `example.com/api/v1/c/d`
      - `example.com/api/a/b`
      - `example.com/api/c/d`
      - `example.com/a/b`
      - `example.com/c/d`
      - `example.com/home/a/b`
      - `example.com/home/c/d`
  - You get a ready `httpx` command in a popup. Edit or copy to run in your terminal.
  - The tool also tries to add the latest `Cookie` or `Authorization` header for that host from Proxy history.
- Send to Repeater
  - Builds a minimal HTTP request for the selected endpoint and sets the `Host` from the Referer.
  - You can add the latest `Cookie` or `Authorization` from Proxy history with one click.
- Add endpoint to Global Ignored
  - Some relative-like values are common in JS and are noise (like `application/zip` or a date format).
  - Adds the selected value to a global ignore file in the Global export directory (`paramamador_global_ignored.txt`).

### NotSure Tab
- Endpoints from less strict JS regex rules.
- Mostly noise, but can have useful finds sometimes.

### Jsluice Tab
- Shows results from the `jsluice` AST scan of JS files.
- You can also send these to Repeater.

## Build Commands

```bash
./gradlew build
./gradlew jar
./gradlew clean
```

Load the JAR from `build/libs/` into Burp: Extensions → Installed → Add.
