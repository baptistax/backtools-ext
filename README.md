# BackTools Export

BackTools Export is a Chrome/Chromium DevTools extension that analyzes the current inspected page and exports a bounded, code-rich ZIP package.

Repository: https://github.com/baptistax/backtools-ext

Public v1 is intentionally simple: run a scan, export the default ZIP, and optionally include a raw cookie dump when you explicitly need it.


**

BackTools is a Chrome DevTools extension that exports a structured capture package from the current website.

It collects useful source files, network response bodies, cookies, application storage metadata, and related reports into a readable ZIP for debugging, investigation, or technical review.

<img width="1885" height="1112" alt="image" src="https://github.com/user-attachments/assets/75972f85-befc-428c-8da0-4b34e7961d68" />



**


## Install locally

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select this repository folder.
5. Open DevTools on a page and choose the **Back Tools** panel.

## Basic use

1. Open BackTools before reload/capture when possible.
2. Set **Scan duration** from 1 to 20 seconds. Default is 5 seconds.
3. Click **Analyze and capture**.
4. Wait for the scan to finish.
5. Click **Export**.

Use a longer scan when the page loads code late after hydration, login, route changes, or dynamic imports. Public v1 is not designed for heavy Analyze/Export runs in multiple BackTools panels at the same time.

## What the export includes

BackTools prefers useful code and text evidence:

- JavaScript, CSS, HTML, JSON, XML, SVG, text, source maps, web manifests, and source-like files exposed by DevTools.
- Network response bodies when Chrome DevTools exposes them.
- Compact reports for Network, Cookies, Application, and Manifest.
- Sanitized cookie and Application storage files.
- IndexedDB and Cache Storage inventories.

BackTools skips noisy/heavy assets by default, including images, fonts, video, audio, large binary files, logs, diagnostics, and raw Application/Web Storage values.

The only optional raw export in public v1 is **Include raw cookie dump**.

## Where to look in the ZIP

Start with these files:
------------------------------------------------------------------------------------------------------------------------------------------------------------------
| Looking for                         |                Open this                    | What to search for                                                         |
|                    ---              |                   ---                       |                        ---                                                 |
| Quick overview                      | `CAPTURE_SUMMARY.md`                        | exported counts,  skipped counts,  capture notes                           |
| Why something did or did not export | `MANIFEST.json`                             | `reasonGroups`,  `skippedResources`,  `bodyPath`,  `sourcePath`            |
| Full manifest details               | `MANIFEST_DETAILS.json`                     | larger resource/detail lists                                               |
| Network requests and bodies         | `NETWORK_REPORT.json`                       | `urlRedacted`,  `mimeType`,  `statusCode`,  `bodyCaptureStatus`,  `bodyPath|
| Verbose network metadata            | `network/NETWORK_DETAILS.json`              | headers/status/detail fields                                               |
| Exported response bodies            | `network/...`                               | actual HTML/JS/CSS/JSON/text files                                         |
| Exported Sources files              | `sources/...`                               | source files exposed by DevTools                                           |
| Cookie summary and findings         | `cookies/COOKIES_REPORT.json`               | `name`,  `domain`,  `flags`,  `risk`,  `sourceUrlCount`                    |
| Sanitized cookie inventory          | `cookies/cookies.sanitized.json`            | masked values,  length,  fingerprint                                       |
| Raw cookie dump, if enabled         | `cookies/cookies.raw.json`                  | unmasked cookie values                                                     |
| Application overview                | `application/APPLICATION_REPORT.json`       | storage counts,  sample keys,  inventories                                 |
| Sanitized Web Storage records       | `application/storage.sanitized.json`        | `id`,  `kind`,  `storageType`,  `key`,  `classification`,  `value`         |
| IndexedDB inventory                 | `application/indexeddb.inventory.json`      | database and object store names                                            |
| Cache Storage inventory             | `application/cache-storage.inventory.json`  | cache names and request metadata                                           |
------------------------------------------------------------------------------------------------------------------------------------------------------------------
Example fields that help when debugging storage variables:

```json
{
  "id": "app:localStorage:...",
  "kind": "application_storage",
  "storageType": "localStorage",
  "key": "example:key",
  "classification": "general",
  "value": {
    "rawIncluded": false,
    "masked": "abcd####",
    "length": 12,
    "fingerprint": { "algorithm": "SHA-256" }
  }
}
```

Example fields that help when debugging network bodies:

```json
{
  "urlRedacted": "https://example.com/app.js",
  "mimeType": "application/javascript",
  "bodyCaptureStatus": "body_captured",
  "bodyPath": "network/example.com/app--hash.js"
}
```

Example fields that help when debugging cookies:

```json
{
  "name": "session_id",
  "domain": ".example.com",
  "flags": { "secure": true, "httpOnly": true, "sameSite": "Lax" },
  "sourceUrlCount": 42,
  "sampleSourceUrls": ["https://example.com/..."]
}
```

## Privacy and security notes

Do not publish captures from logged-in sessions unless you have reviewed them.

By default:

- cookie and storage values are masked;
- sanitized files preserve metadata, masks, lengths, and fingerprints;
- URL query values, fragments, token-like path values, and risky URL parameters are redacted in reports and manifests;
- raw Application/Web Storage export is disabled in public v1;
- raw cookie values are exported only when **Include raw cookie dump** is enabled.

Raw cookie dumps can contain session secrets. Keep them private.

## Current limitations

- ZIP generation happens in the DevTools panel process with JSZip and can be memory-heavy on very large captures.
- Network response bodies are available only when Chrome DevTools exposes them.
- Sources resources vary by site and timing.
- BackTools does not use CDP, `chrome.debugger`, Fetch interception, runtime injection, a backend service, or the browser cookie store.
- Full IndexedDB record dumps and full Cache Storage response body dumps are out of scope for public v1.


## License

This project is currently released as **All Rights Reserved**. See `LICENSE`.

JSZip is included locally under its own license in `lib/JSZip-LICENSE.markdown`.
