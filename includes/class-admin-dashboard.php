<?php
/**
 * Admin Dashboard.
 * 
 * Provides:
 *  - Top-level admin menu: Urban Canvas.
 *  - Submission review with event-type filtering.
 *  - Audit Log viwer with event-type filtering.
 *  - Security overview (integrity status, lockout stats, blocked uploads).
 *  - Secure file download endpoint for private submission files.
 * 
 * @package UrbanCanvas
 */

namespace UrbanCanvas;

defined('ABSPATH') || exit;