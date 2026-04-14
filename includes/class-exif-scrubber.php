<?php
/**
 * EXIF / Metadata Scrubber.
 * 
 * Automatically strips ALL EXIF, IPTC, GPS, and XMP metadata from every image uploaded through the Urban Canvas
 * portal, protecting the privacy and physical locations of youth participants.
 * 
 * Strategy:
 *      - JPEG/PNG: re-encode through GD (lossy-free at quality 100) which discards all metadata by design - GD never copies
 *        EXIF to output.
 *      - PDF: metadata scrubbing via string-level stripping is unreliable; the plugin logs a warning and stores PDFs in a
 *        non-web-accessable directory under /private/ to prevent direct hotlinking.
 * 
 * Hooks into our submission handler (not wp_handler_upload) to ensure scrubbing occurs BEFORE the file is moved to its
 * final location.
 * 
 * @package UrbanCanvas
 */

namespace UrbanCanvas;

defined('ABSPATH') || exit;

class Exif_Scrubber {
    public function init(): void {
        add_filter('uc_before_store_upload', [$this, 'scrub'], 5);
    }

    /**
     * Strips metadata from the temporary upload path.
     * Returns the (possibly new) temp path on success, or throws on failure.
     * 
     * @param array{tmp_path:string,mime:string,safe_name:string} $upload
     * 
     * @return array Same structure, tmp_path pointing to scrubbed file. 
     * 
     * @throws \RuntimeException On unrecoverable scrub failure.
     */
}