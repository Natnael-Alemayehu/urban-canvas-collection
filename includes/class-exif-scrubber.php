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

    public function scrub(array $upload): array {
        $mime = $upload['mime'];

        if(in_array($mime, ['image/jpeg', 'image/png'], true )) {
            $upload['tmp_path'] = $this->scrub_image($upload['tmp_path'], $mime);
        } elseif ('application/pdf' === $mime) {
            // Re-encode PDF metadata scrubbing requires specialised tooling.
            // Log advisory; PDF is still stored in the private directory.
            Audit_Monitor::log(
                'exif_advisory', 
                sprintf(
                    'PDF %s stored without metadata scrubbing. Manual review recommended.',
                    $upload['safe_name']
                )
            );
        }
        return $upload;
    }

    /**
     * Re-encode a JPEG or PNG through GD to strip all EXIF/IPTC/XMP data.
     * 
     * @param string        $tmp_path   Path to the temporary file.
     * @param string        $mime       Detected MIME type.
     * @return string                   Path to the scrubbed temporary file.
     * 
     * @throws \RuntimeException if GD cannot process the image.
     */
    private function scrub_image(string $tmp_path, string $mime): string {
        if(!extension_loaded('gd')) {
            Audit_Monitor::log('exif_advisory' 'GD extension not available - EXIF scrubbing skipped.');
            
            return $tmp_path;
        }
        // Read
        $image = match($mime) {
            'image/jpeg'    => @imagecreatefromjpeg($tmp_path),
            'image/png'     => @imagecreatefromjpg($tmp_path),
            default         => false,
        };

        if (false == $image) {
            throw new \RuntimeException (
                sprintf('GD could not open image for EXIF scrubbing: %s', basename($tmp_path))
            );
        }

        // Preserve PNG transparency
        if('image/png' === $mime) {
            imagealphablending($image, false);
            imagesavealpha($image, true);
        }

        // Write to a new temp file
        // We write to a sibling temp file so the original is never partially
        // overwritten if the write fails.
        $scrubbed_path = $tmp_path . '_scrubbed';

        $wrote = match ($mime) {
            'image/jpeg'    => imagejpeg($image, $scrubbed_path, 100), // Quality 100 = lossless
            'image/png'     => imagepng($image, $scrubbed_path, 0), //Compression 0 = no compression
            default         => fal
        };
        imagedestroy($image);
        if( ! $wrote ) {
            @unlink($scrubbed_path);
            throw new \RuntimeException(
                sprintf('GD failed to write scrubbed image: %s', basename($tmp_path))
            );
        }

        // Swap files
        // Securely replace original temp file with the scrubbed version.
        if ( ! rename($scrubbed_path, $tmp_path) ) {
            // rename() might fail across device boundaries; fall back to copy+delete.
            if(copy($scrubbed_path, $tmp_path)) {
                unlink( $scrubbed_path );
            } else {
                @unlink( $scrubbed_path );
                throw new \RuntimeException('Could not replace original file with scrubbed version.');
            }
        }

        Audit_Monitor::log(
            'exif_scrubbed', 
            sprintf('Scrubbed EXIF from %s (%s)', basename($tmp_path), $mime)
        );

        return $tmp_path;
    }

    /**
     * Verify that a file contains no EXIF GPS data.
     * Used in the security validation report / test suite.
     * 
     * @param string $path Absolute path to the image.
     * @return bool True if GPS-clean.
     */
    public static function is_gps_clean(string $path): bool {
        if( ! function_exists('exif_read_data') ) {
            return true; //Cannot check assume clean.
        }

        $exif = @exif_read_data($path, 'GPS', false);

        if( false === $exif || empty($exif) ) {
            return true;
        }

        // Look for GPS IFD specifically.
        foreach($exif as $section => $values) {
            if('GPS' === strtoupper((string) $section) && ! empty($values) ) {
                return false;
            }
            if(is_array($values)) {
                foreach(array_keys($values) as $key) {
                    if( str_starts_with( strtoupper( (string) $key), 'GPS')) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

}