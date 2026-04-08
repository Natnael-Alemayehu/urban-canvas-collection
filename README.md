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