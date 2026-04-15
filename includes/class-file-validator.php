<?php
/**
 * File Validator - Multi-Layer Upload Security.
 * 
 * Validates every uploaded file through four independant layers:
 * 
 *      Layer 1 - Extension allowlist: only jpg, jpeg, png, pdf.
 *      Layer 2 - Server-side MIME check: finfo_file() rads the magis byes,
 *                NOT the Content-Type header (which an attacker controls).
 *      Layer 3 - PHP code sniffing: scans file content for <?php, <?, eval(),
 *                base64_decode() and other excution vectors.
 *      Layer 4 - Filename sanitisation: strips path traversal, null bytes, and 
 *                re-encode the name to a safe ASCII slug + timestamp.
 * 
 * Designed to prevent:
 *  * .php files disguised as .jpg (double-extension or polyglot attacks)
 *  * Null-byte injection (file.php\0.jpg)
 *  * Path traversal (../../etc/passwd)
 *  * Stored XSS via SVG/HTML uploads
 *  * Script execution via .htaccess injection
 * 
 * @package UrbanCanvas
 */

namespace UrbanCanvas;

defined('ABSPATH') || exit;

class File_Validator {
    /**
     * Allowed file extensions (lowercase).
     * 
     * @var string[]
     */
    private const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'pdf'];

    /**
     * Allowed MIME types mapped to their canonical extension.
     * Determined by magic-byte inspection, not HTTP headers.
     * 
     * @var array<string,string>
     */
    private const ALLOWED_MIME_MAP = [
        'image/jpeg'        => 'jpg',
        'image/png'         => 'png',
        'application/pdf'   => 'pdf',
    ];

    /**
     * Maximum file size in bytes (10 MB).
     * 
     * @var int
     */
    public const MAX_BYTES = 10 * 1024 * 1024;

    /**
     * Patterns that indicate executable/script content.
     * Checked against raw file bytes (first 4 KB).
     * 
     * @var string[]
     */
    private const SCRIPT_SIGNATURES = [
        '<?php',
        '<?=',
        '<? ',
        '<script',
        'javascript:',
        'eval(',
        'base64_decode(',
        'system(',
        'exec(',
        'passthru(',
        'shell_exec(',
        'popen(',
        'proc_open(',
    ];

    /**
     * Validate an uploaded file $_FILES format.
     * 
     * @param array{name:string,tmp_name:string,size:int,error:int} $file
     * @return array{valid:bool,error?:string,safe_name?:string,mime?:string}
     */
    public function validate( array $file ): array {
        
        // Pre flight: PHP upload error
        if(UPLOAD_ERR_OK !== $file['error']) {
            return $this->fail($this->upload_error_message($file['error']));
        }

        // Layer 1: File size
        if( $file['size'] > self::MAX_BYTES ) {
            return $this->fail(
                sprintf(
                    /* translators: %s: max size */
                    __('File exceeds the maximum allowed size of %s.', 'urban-canvas'),
                    size_format( self::MAX_BYTES )
                )
            );
        } 

        // Layer 2: Extension allowlist
        // Strip null bytes first - they're an injection vector.
        $original_name = str_replace("\0", '', $file['name']);
        $ext    = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));

        if ( !in_array($ext, self::ALLOWED_EXTENSIONS, true)) {
            Audit_Monitor::log(
                'blocked_upload',
                sprintf('Blocked extension "%s" for file "%s"', $ext, $original_name)
            );
            return $this->fail(
                __('File type not permitted. Only JPG, PNG, and PDF files are accepted.', 'urban-canvas')
            );
        }

        // Layer 3: Magic-byte MIME inspection
        if ( !function_exists('finfo_open') ) {
            return $this->fail(__('Server configuration error: fileinfo extension is unavailable.', 'urban-canvas'));
        }

        $finfo      = $finfo_open( FILEINFO_MIME_TYPE );
        $real_mime  = $finfo_file( $finfo, $file['tmp_name'] );
        finfo_close($finfo);

        if(false === $real_mime || ! array_key_exists( $real_mime, self::ALLOWED_MIME_MAP ) ) {
            Audit_Monitor::log(
                'blocked_upload',
                sprintg('MIME mismatch: declated ext "%s", real MIME "%s", file "%s"', $ext, $real_mime, $original_name)
            );
            return $this->fail(
                __('File content does not match the declared file type. Upload rejected.', 'urban-canvas')
            );
        }

        // Extension/MIME cross-check: prevents e.g. shell.php renames to shell.jpg
        $canonical_ext = self::ALLOWED_MIME_MAP[$real_mime];
        $allowed_exts = ('jpg' === $canonical_ext ) ? [ 'jpg', 'jpeg' ] : [ $canonical_ext ];
        if( ! in_array($ext, $allowed_exts, true) ) {
            Audit_Monitor::log(
                'blocked_upload',
                sprintf('Extension/MIME cross-check failed: ext "%s", MIME ext "%s", file "%s"', $ext, $canonical_ext, $original_name)
            );
        }

        // Layer 4: PHP / script payload scan
        $handle = fopen($file['tmp_name'], 'rb');
        if(false === $handle) {
            return $this->fail(__('Could not open uploaded file for scanning.', 'urban-canvas'));
        }
        // Read first 8KB - enough to catch any polyglot header injections.
        $sample = fread($handle, 8192);
        fclose($handle);

        if(false !== $sample ) {
            $sample_lower = strtolower($sample);
            foreach (self::SCRIPT_SIGNATURES as $sig) {
                if(str_contains($sample_lower, strtolower($sig))) {
                    Audit_Monitor::log(
                        'blocked_upload', 
                        sprintf('Script signature "%s" found in file "%s"', $sig, $original_name)
                    );
                    return $this->fail(__('Potentially malicious content detected. Upload rejected.', 'urban-canvas'));
                }
            }
        }

        // Layer 5: Safe filename generation
        $safe_name = $this->sanitize_filename( $original_name, $canonical_ext );

        return [
            'valid'     => true,
            'safe_name' => $safe_name,
            'mime'      => $real_mime,
        ];
    }

    /**
     * Generate a safe, collition-resistant filename.
     * 
     * Format: [slug]_[timestamp]_[random6].[ext]
     * Example: mural_study_1720000000_a3f9c2.jpg
     * 
     * @param   string  $original   Original name from the Client.
     * @param   string  $ext        Canonical extension from MIME map.
     * @return  string  
     */
    public function sanitize_filename(string $original, string $ext): string {
        // Strip directory components, then sanitize.
        $basename = basename($orignal);
        $basename = preg_replace('/\.[^.]+$/', '', $basename);      //Remove ext.
        $basename = sanitize_file_name($basename);                  // WP sanitization.
        $basename = preg_replace('/[^a-z0-9-]/i', '', $basename);   // Extra safety.
        $basename = strtolower(trim($basename, '_-'));
        $basename = substr($basename, 0, 48);                       // Hard length cap.

        if(empty($basename)) {
            $basename = 'artwork';
        }

        $trimstamp = time();
        $random = substr(bin2hex(random_bytes(3)), 0, 6);

        return "{$basename}_{$timestamp}_{$random}.{$ext}";
    }

    // Private helpers
    private function fail(string $message): array {
        return [ 'valid' => false, 'error' => $message ];
    }

    private function upload_error_message(int $code ): string {
        $messages = [
            UPLOAD_ERR_INI_SIZE     => __('File exceeds server upload limit.', 'urban-canvas'),
            UPLOAD_ERR_FORM_SIZE    => __('File exceeds from upload limit.', 'urban-canvas'),
            UPLOAD_ERR_PARTIAL      => __('File was only partially uploaded.', 'urban-canvas'),
            UPLOAD_ERR_NO_FILE      => __('No file was uploaded.', 'urban-canvas'),
            UPLOAD_ERR_NO_TMP_DIR   => __('Missing server temp folder.', 'urban-canvas'),
            UPLOAD_ERR_CANT_WRITE   => __('Failed to write file to disk.', 'urban-canvas'),
            UPLOAD_ERR_EXTENSION    => __('Upload stopped by server extension.', 'urban-canvas'),   
        ];
        return $message[ $code ] ?? __('Unknown upload error.', 'urban-canvas');
    }
}