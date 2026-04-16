# Urban Cancas Collection - Hardened Submission Portal

> A production-grade WordPress security plugin rebuilding the Urban Canvas Collective art submission portal from the ground up after a breach involding malicious file uploads and SQL injection.

---

## Table of Contents

1. [Security Architecture Overview](#security-architecture-overview)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Feature Deep-Dives](#feature-deep-dives)
    - [1. Hardened File Upload Validation](#1-hardened-file-upload-validation)
    - [2. Infrasrtucture Obfuscation](#2-infrasrtucture-obfuscation)
    - [3. EXIF / Metadata Scrubbing](#3-exif--metadata-scrubbing)
    - [4. Zero-Trust User Roles](#4-zero-trust-user-roles)
    - [5. Audit & Integrity Monitoring](#5-audit--integrity-monitoring)
    - [6. Performance Considerations](#6-performance-considerations)
5. [wp-config.php Hardening](#wp--condigphp-hardening)
6. [Server-Level Hardening (.htaccess)](#server-level-hardening-ht-access)
7. [Secutiry Validation - Test Cases](#security-validation--test-cases)
8. [Admin Dashboard Reference](#admin-dashboard-reference)
9. [Artist Onboarding Guide](#artist-onboarding-guide)
10. [Incident Response Checklist](#incident-response-checklist)

---

## Secutiry Architecture Overview

```
        Incoming Request
                |
                |
------------------------------------------------
|       Infrastrusture Hardening               |
| * Custom login URL    *XML-RPC disabled      |
| * REST API locked     *Security headers      |
| * Version info stripped                      |
------------------------------------------------
                |
                |
------------------------------------------------
|          Zero-Trust Auth Gate                |
| * uc_trust role       * No dashbaord access  |
| * REST API locked     * Rate limiting (5/day)|
| * Brute-force lockout (5 attempts -> 15 min) |
------------------------------------------------
                |
                | (file uploads only)
------------------------------------------------
|          4-Layer File Validation             |
| Layer 1: Extension allowlist (jpeg/png/pdf)  |
| Layer 2: Magic-byte MIME check (finfo_file)  |
| Layer 3: Extension x MIME cross-check        |
| Layer 4: PHP/script payload scan (8kb sample)|
------------------------------------------------
                |
                |
------------------------------------------------
|          EXIF / GPS scrubber                 |
| * GD re-encode at quality 100 (JPEG/PNG)     |
| * All metadata blocks stripped               |
| * PDF advisoty logged for manual review      |
------------------------------------------------
                |
                |
------------------------------------------------
|       Private Storage + DB Record            |
| * Stored outside web root                    |
| * chmod 640   * .htaccess PHP-exec block     |
| * uc_submission CPT   * Full audit trail     |
------------------------------------------------
```

## Requirements
| Requirement | Version |
|--- | ---|
| wordpress | 6.0.0 +|
|PHP | 8.1+ |
|PHP extensions | `gd`, `fileinfo`, `mbstring` |
| web server | Apache (mod_rewrite) or Nginx |
|https | required (application passwords, HSTS) |

---

## Installation

### 1. Plugin

```bash
#Via ZIP upload (highly recommended for prod)
WP admin-> Plugins -> Add New -> Upload Plugin -> urban-canvas-security.zip

#via WP-CLI
wp plugin install urban-canvas-security.zip --activate
```

### 2. Custom database prefix (BEFORE first WP install)

Edit`wp-config.php`:
```php
$table_prefix = 'uc8xq3_'; // Any random 6-8 character string
```
> If WP is already installed, use the [Brozzme DB Prefix plugin]{https://wordpress.org/plugins/search/brozzme-db-prefix-change-new/} to migrate safely.

### 3. Apply wp-config hardening constants

Copy all constants from `wp-cofig-hardening.php` into your `wp-config.php` before the stop-editing comment.

### 4. Verify activation

Go to **WP Admin -> Urban Canvas -> Security** and confirm all rows show active.

---

## Feature Deep-Dives

### 1. Hardening File Upload Validation
**Class** `File_Validator`
**Location:** `includes/class-file-validator.php`

The validation pipeline is intentionally redundant - an attacker must defeat all four independant layers simultaneously.

### Layer 1- Extension allowlist

```php
private const ALLOWRD_EXTENSIONS = ['jpg', 'jpeg', 'png', 'pdf'];
```
Null bytes are stripped before the extension is parsed, blocking the classis `file.php\0.jpg` attack.

### Layer 2- Magic-byte MIME inspection

```php
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$real_mime = finfo_file($finfo, $file['tmp_name']); 
```

This reads the actual bytes on disk -- not the 'Content-Type' header, which an attacker fully controls. A PHP file renamed
to '.jpg' will reveal its `text/x-php` MIME type here.

### Layer 3 - Extension X MIME cross-check

```
Declared extension: .jpg
Real MIME from bytes: application/pdf
-> REJECTED - mismatch
```

### Layer 4 - PHP / script payload scan

The frist 8 KB of every file is scanned fro 13 execution signatures:

```
<?php <?= <?(space) <script javascript:
eval (base64_decode(system(exec( passthrough(
shell_exec( popen( proc_open(
```

Polyglot files (valid JPEG with embedded php payload) are caught at this layer even if they pass layers 1-3.

#### Safe filename generation

```
{slug}_{unix_timestamp}_{6-byte-random}.{ext}
mural_study_1720000000_a3f9c2.jpg
```

- Maximum 48 characters for the slug
- No path separators, null bytes, or shell metacharacters
- Collision-resistant via timestamp + random suffix

---

### 2. Infrastructure Obfuscation
**class:** `infrastructure_Hardening`

#### XML-RPC

```php
add_filter('xmlrpc_enabled','__return_false');
```
All methods disabled. The `xmlrpc_call` action additionally terminates execution with `HTTP 403`.

#### REST API restriction
Unauthenticated requests to all `wp/v2/*` rotues receive:
```json
{"code": "uc_rest_forbidden", "message": "REST API access requires authentication.", "data":{"status":401}}
```
Our own public `/uc/*` namespace is whitelisted.

#### Custom login URL

The default `wp-login.php` returns **HTTP 404** for direct access. The real login is served at: 
```
https://test.isadethiopia.com/uc-portal-login/
```
Change the slug: **WP Admin -> Settings -> General ** or directly: `update_option('uc_login_slug', 'your-slug')`.

#### Security response headers
|Header|Value|
|---|---|
|`X-Frame-Options`|`SAMEORIGIN`|
|`X-Content-Type-Options`|`nosniff`|
|`Content-Security-Policy`|`default-src 'self';frame-ancestors 'none'; ...`|
|`Strict-Transport-Security`|`max-age=31536000; includeSubDomains`|
|`Permission-Policy`|`geolocation=(), microphone=(), camera=()`|
|`Referrer-Policy`|`strict-origin-when-cross-origin`|

---

### 3. EXIF / Metadata Scrubbing

**Class:** `Exif_Scrubber`

Every JPEG and PNG is re-encoded through PHP's GD library immediately after validation, **before** being moved to permanent
storage:

```
Original file (with GPS, camera model, timestamp, etc.)
    | imagecreatefromjpeg() - GD reads pixed data only
    | imagejpeg($image, $path, 100) - GD writes clean pixels
Clean file (zero metadata blocks)
```

GD's `imagejpeg()` and `imagepng()` functions write only pixel data to the output stream - they have no mechanism to forward EXIF, IPTC, XMP, or GPS IFDs. This is more reliable that EXIF-stripping libraries that attempt to find and remove specific byte ranges.
**Verification:** Use `exiftool output.jpg` to confirm the GPS IFD is absent.

**PDF advisory:** GD cannot process PDFs. PDFs are flagged in the audit log for manual metadata review and are stored in the private non-web-accessible directory.

---

### 4. Zero-Trust User Roles

**Class:**`Artist_Role`

The `uc_artist` role is created on plugin activation with the absolute minimum capabilities:

|Capability|Value|Reason|
|---|---|---|
|`read`|`true`|Required by WP for any authenticated request|
|`uc_submit_artwork`|`true`|Custom cap checked in submission handler|
|`upload_files`|`false`|Prevents media library access|
|All other caps|not set|Denied by default|

**Dashboard block:** `admin_init` fires a `wp_safe_redirect()` to `/submit/` for any Artist attempting to access `wp-admin`. Admin bar is hidden entirely.

**Map meta cap override:** `edit_post`, `delete_post`, and publish caps all return `do_not_allow` for the Artist role - they cannot modify their submissions once created.

---

### 5. Audit & integrity Monitoring

**Class:** `Audit_Monitor`

#### Audit log table schema

```sql
CREATE TABLE wp_uc_audit_log(
    id              BIGINT(20) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_type      VARCHAR(64) NOT NULL, -- snake_case event ID
    message         TEXT        NOT NULL,
    ip_address      VARCHAR(45) NOT NULL DEFAULT '',
    user_id         BIGINT(20)  NOT NULL DEFAULT 0,
    created_at      DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_event_type(event_type),
    KEY idx_created_at(created_at)
);
```

#### Event types

|Event|Trigger|Alert?|
|---|---|---|
|`blocked_upload`|File failed validation| EMAIL|
|`login_failed`|Wrong password| No|
|`lockout`|5th failed attempt| EMAIL|
|`lockout_blocked`|Request from locked IP| No|
|`login_probe`|Direct wp-login.php access| EMAIL|
|`file_change_detected`|Core file hash changed| EMAIL|
|`rest_blocked`|Unauthenticated REST call| No|
|`exif_scrubbed`|GPS stripped from image| No|
|`submission_ok`|Successful submission| No|
|`csrf_failed`|Nonce verification faild| No|
|`integrity_ok`|Daily Scan passed| No|

#### Brute-force protection

```
Failed login -> increment transient uc_fails_{md5(IP)}
5th failure -> set transient uc_locked_{md5(IP)} (TTL: 900 seconds)
            -> send admin email alert
Locked IP   -> wp_die() with HTTP 429 on next attempt
Success     -> both transients deleted
```

#### File integrity monitoring

Daily `wp-cron` job hashes 7 critical WP core files with SHA-256. On first run, a baseline is storred in `wp_options`. Subsequent runs comapre hashes and email the admin if any file has changed. Rebuild the baseline intentionally after WP core updates via **Urban Canvas -> Security -> Rebuild Baseline**.

---

### 6. Performance Considerations
- **EXIF scrubbing:** GD re-encoding happens in memory (no disk I/O besides the final write). For a 10 MB JPEG at quality 100, this typically takes 200-400 ms - acceptable for a submission portal.
- **File scanning:** Reading 8 KB from the file for script signature detecteion adds < 5ms.
- **Audit log:** The `uc_audit_log` table uses indexed columns (`event_type`, `created_at`). Log rows are pruned weekly to a maximum of 10,000 entries.
- **Integrity monitoring:** Cron-based (daily), runs outside the request cycle. No inpact on page load.
- **Security headers:** Pure PHP header injection - zero overhead.
- **Gallery performance:** The plugin does not modify frontend image delivery. Pair with a CDN (Cloudflare, BunnyCDN) for high-resolution gallery performance.

---

## wp-config.php Hardening

See `wp-config-hardening.php` for the full annotated set of constants. Critical Items:

```php
$table_prefix           = 'uc8xq3_'; // Non-default prefix
define('DEFINE_FILE_EDIT', true); // Kill editor in admin
define('DESALLOW_FILE_MODS', true); // Kill plugin/theme install
define('FORCE_SSL_ADMIN', true); // HTTPS-only admin
define('WP_DEBGU', false); // No error disclosure in prod
```

---

## Server-Level Hardening (.htaccess)

The plugin writes ruls automatically to '/wp-content/uploads/.htaccess':
```apache
# Block PHP execution in uploads
<FilesMatch "\.(?i:php[0-9]?|phtml|phar|phps|pl|cgi|asp|aspx|jsp|sh|bash)$">
    Require all denied
</FilesMatch>

Options -indexes
```

**Recommended additinos to the root `.htaccess`:**

```apache
# Block access to sensative files
<FilesMatch "^(wp-config\.php|xmlrpc\.php|readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>

# Prevent directroy traversal
RewriteRule ^.*\.\./.*$-[F,L]

# Block common scan patterns
RewriteCond %{QUERY_STRING}(\<|%3C).*script.*(\>|%3E) [NC,OR]
RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]
RewriteCond %{QUERY_STRING} _REQUEST(=|\[%[0-9A-Z]{0.2})
RewriteRule .* index.php [F,L]
```

---

Security Validation - Test Cases

These tests demonstrate the system activel rejecting attacks.

### TC-01: PHP file disguised as JPG

```bash
# Create a PHP webshell with JPEG magic bytes pretended
printf '\xff\xd8\xff\xe0<?php system($_GET["cmd"]);?>' > evil.jpg

# Submit via curl
curl -X POST https://test.isadethiopia.com/wp-admin/admin-ajax.php \
    -b "wordpress_logged_in_XXX=..." \
    -F "action=uc_submit_artwork" \
    -F "nonce=YOUR NONCE" \
    -F "artist_name=Test" \
    -F "artwork_title=Test" \
    -F "artwork_file=@evil.jpg;type=image/jpeg" \
```

**Expected:** `HTTP 422` - `"Potentially malicious content detected. Upload rejected."`
**Audit log:** `blocked_upload - Script signature "<?php" found in file "evil.jpg"`

### TC-02: Double extension attack

```bash
mv shell.php shell.php.jpg
# Submit shell.php.jpg
```

**Expected:** Layer 3 (MIME cross-check) - `"File extension does not match file content."`

### TC-03: Unauthenricated REST access
```bash
curl https://test.isadethiopia.com/wp-json/wp/v2/users
```
**Expected:** `HTTP 401` - `{"code":"uc_rest_forbidden"}`

### TC-04: Brute-force login

```bash
for i in $(seq 1 6);do
    curl -X POST https://test.isadethiopia.com/uc-portal-login/\
    -d "log=admin&pwd=wrongpassword&wp-submit=Log+In"
done
```

**Expected:** 6th attempt returns `HTTP 429` - `"Too many failed login attempts."`
**Audit log:** `lockout` event with email alert sent to admin.

### TC-05: Direct wp-login.php access

```bash
curl -l https://test.isadethiopia.com/wp-login.php
```

**Expected:** `HTTP 404`
**Audit log:** `login_probe event.`

### TC-06: GPS metadata stripped

```bash
# Submit a photo with GPS coordinates
exiftool downloaded.jpg | grep GPS # Returns: (nothing)
```

**Expected:** Empty GPS output.

### TC-07: Artist cannor access wp-admin
1. Login as an Artist user.
2. Navigate to `/wp-admin/`.

**Expected:** immediate redirect to `/submit/`. Admin bar not shown.

---

## Admin Dashbaord Reference

|Menu|Purpose|
|---|---|
|Urban Canvas -> Security|Hardening status overview, stat cards, recent audit events|
|Urban Canvas -> Submissions|Review, filter, and downlaod submitted artwork|
|Urban Canvas -> Audit Log|Full filterable event log|

**Secure file download:** All netwoek is stored outside the web root. Admins downlaod files via a signed URL(`admin-ajax.php` wth nonce) that validates the file path is within the private submissions directory.

---

## Artist Onboarding Guide

1. Admin creates a WordPress user with role **Artist**.
2. Artist receives login credentials and the custom login URL (not `wp-login.php`).
3. Artist navigates to the submission page (e.g., `https://test.isadethiopia.com/submit/`).
4. Artist completes the form and uploads their network.
5. Admin receives an email notification and reviews the Submission in **Urban Canvas -> Submissions**.

Artists never see wp-admin, the media library, or any other WordPress internals.

---

## Incident Response Checklist

If a breach is suspected:
- [] **Rotate credentials:** Change all WP admin passwords and Application Passwords.
- [] **Check audit log:** Urban Canvas -> Audit Log, filter by `blocked_upload`, `file_change_detected`.
- [] **Rebuild integrity baseline:** (after verifying files are clean): Urban Canvas -> Security -> Rebuild Baseline.
- [] **Scan private submissions directory:** `grep -r "<?php" /var/www/wp-cotent/uc-private-submissions/`
- [] **Rotate auth keys/salts** in `wp-config.php` (logs out all users).
- [] **Review server access logs** for suspicious patterns.
- [] **Notify affected users** if student data was accessed.
