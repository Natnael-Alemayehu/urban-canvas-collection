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

#### Layer 4 - PHP / script payload scan

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

