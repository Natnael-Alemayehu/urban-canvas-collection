<?php
/**
 * Submission Handler.
 * 
 * Orchestrates the front-end artwork submission pipeline:
 * 
 *      1. Renders the secure submission form via [uc_submission_form] shortcode.
 *      2. Processes the AJAX POST, including CSRF (nonce) verification.
 *      3. Rate-limits submission per authenticated user.
 *      4. Pass the upload through File_Validator (4-layer check).
 *      5. Fires the uc_before_store_upload filter so Exif_Scrubber runs.
 *      6. Stores the file in a private directory OUTSIDE the web root.
 *      7. Creates a uc_submission CPT record with sanitized meta.
 *      8. Logs the event to the audit log.
 * 
 * @package UrbanCanvas
 */

namespace UrbanCanvas;

defined ( 'ABSPATH' ) || exit;

class Submission_Handler{
    /** AJAX action name. */
    private const AJAX_ACTION = 'uc_submit_artwork';

    // Max submissions per user per day.
    private const RATE_LIMIT = 5;

    // Private storage directory (relative to wp-content).
    private const PRIVATE_SUBDIR = 'uc-private-submissions';

    public function init(): void {
        add_shortcode('uc_submission_form', [$this, 'render_form']);
        add_action('wp_ajax_' . self::AJAX_ACTION, [$this, 'handle_submission']);
        add_action('wp_ajax_nopriv_' . self::AJAX_ACTION, [$this, 'reject_unauthenticated'] );
        add_action('wp_enqueue_scripts', [$this, 'enqueue_assets']);
    }

    // Asset Registration

    public function enqueue_assets(): void {
        if (! is_page()) {
            return;
        }

        wp_enqueue_style(
            'uc-submission',
            UC_PLUGIN_URL . 'assets/css/submission-form.css',
            [], 
            UC_VERSION
        );

        wp_enqueue_script(
            'uc-submission', 
            UC_PLUGIN_URL . 'assets/js/submission-form.js',
            ['jquery'],
            UC_VERSION,
            true
        );

        wp_localize_script(
            'uc-submission',
            'ucSibmit',
            [
                'ajaxurl'       => admin_url('admin_ajax.php'),
                'nonce'         => wp_create_nonce(self::AJAX_ACTION),
                'action'        => self::AJAX_ACTION,
                'maxSizeMB'     => round(File_Validator::MAX_BYTE / 1048567, 1),
                'i18n'          => [
                    'uploading'     => __('Uploading and scanning your field', 'urban-canvas'),
                    'success'       => __('Your submission has been recieved! We\'ll be in touch soon.', 'urban-canvas'),
                    'fileTooBig'    => __('File is too large. Maximum size is %s MB.', 'urban-canvas'),
                    'wrongType'     => __('Only JPG, PNG, and PDF files are accepted.', 'urban-canvas'),
                    'mustLogin'     => __('Please log in to submit your artwork.', 'urban-canvas'),
                    'rateLimit'     => __('You have reached your daily submission limit.', 'urban-canvas'), 
                ],
            ]
        );
    }

    // Shortcode

    public function render_form(array $atts): string {
        if( ! is_user_logged_in() ) {
            return sprintf(
                '<div class="uc-notice uc-notice--warning"><p>%s <a href="%s">%s</a></p></div>',
                esc_html__('You must be logged in to submit artwork.', 'urban-canvas'),
                esc_url(wp_login_url(get_permalink())),
                esc_html__('Log in here.', 'urban-canvas')
            );
        }

        $user = wp_get_current_user();
        if( ! $user -> has_cap('uc_submit_artwork') ) {
            return '<div class="uc-notice uc-notice--error"><p>' . 
                    esc_html__('Your account is not authorised to submit artwork.', 'urban-canvas').
                    '</p></div>';
        }
        ob_start();
        load_template( UC_PLUGIN_DIR . 'template/submission-form.php', false, $atts );
        
        return ob_get_clean();
    }

    // AJAX Handlers
    public function reject_unauthenticated(): void {
        Audit_Monitor::log(
            'unauthenticated_submit',
            'Unauthenticated user attempted to submit artwork.'
        );
        wp_send_json_error(
            ['message' => __('Authentication required.', 'urban-canvas' ) ],
            401
        );
    }

    public function handle_submission(): void {
        // CSRF verification
        if( ! check_ajax_referer(self::AJAX_ACTION, 'nonce', false) ) {
            Audit_Monitor::log( 'csrf_failed', 'Submission CSRF check failed.' );
            wp_send_json_error( ['message' => __('Security check failed. Please refresh and try again.', 'urban-canvas')], 403 );
        }

        // Auth gate
        $user = wp_get_current_user();
        if( ! $user->ID || ! $user->has_cap('uc_submit_artwork') ) {
            wp_send_json_error(['message' => __('You are not authorised to submit.', 'urban-canvas')], 403 );
        }

        // Rate limiting
        $rate_key = 'uc_rate_'. $user_ID . '_' . gmdate('Ymd');
        $submissions = (int) get_transient($rate_key);
        if( $submissions >= self::RATE_LIMIT ) {
            Audit_Monitor::log('rate_limited', sprintf('User #%d hit daily submission rate limit.', $user->ID));
            wp_send_json_error(['message' => __('You have reached your daily submission limit. Please try again tomorrow.', 'urban-canvas')], 429 );
        }

        // Required text fields
        $artist_name = sanitize_text_field(wp_unslash($_POST['artist_name'] ?? '' ));
        $artist_bio = sanitize_textarea_field(wp_unslash($_POST['artist_bio'] ?? '' ));
        $artist_title = sanitize_text_field(wp_unslash($_POST['artwork_title'] ?? ''));
        $artist_desc = sanitize_textarea_field(wp_unslash($_POST['artwork_desc'] ?? ''));

        if( empty( $artist_name ) || empty( $artist_title ) ) {
            wp_send_json_error(['message' => __('Artist name and artwork title are required.', 'urban-canvas')], 400 );
        }

        // Length caps.
        if(mb_strlen($artist_name) > 100 || mb_strlen($artist_title) > 200 ) {
            wp_send_json_error(['message' => __('Text fields exceed maximum allowed length.', 'urban-canvas')], 400);
        }

        // File required
        if( empty($_FILES['artwork_file']) || UPLOAD_ERR_OK !== (int) $_FILES['artwork_file']['error'] ) {
            wp_send_json_error( ['message' => __('Please attach an artwork file.', 'urban-canvas')], 400 );
        }

        // 4 - layer file validation
        $validator = new File_Validator();
        
        // phpcs:ignore WordPress.Security.ValidateSanitizedInput.InputNotSanitized
        $validation = $validator -> validate($_FILES['artwork_file']);

        if ( ! $validation['valid'] ) {
            wp_send_json_error(['message' => $validation['error']], 422);
        }

        // EXIF scrubbing via filter
        $upload_data = [
            'tmp_path'      => $_FILES['artwork_file']['tmp_name'],
            'mime'          => $validation['mime'],
            'safe_name'     => $validation['safe_name'],
        ];

        try {
            $upload_data = apply_filters('uc_before_store_upload', $upload_data); 
        } catch (\RuntimeException $e) {
            Audit_Monitor::log('scrub_error', $e->getMessage());
            wp_send_json_error( ['message' => __('File processing failed. Please try again.','urban-canvas')], 500 );
        }

        // Move to private storage
        $dest_path = $this->get_private_dir() . '/' . $validation['safe_name'];

        if ( ! move_uploaded_file( $upload_data['tmp_path'], $dest_path ) ) {
            Audit_Monitor::log('store_failed', sprintf('Failed to move %s to private storage.', $validation['safe_name']));
        }

        // Restrict file permissions.
        chmod( $dest_path, 0640 );

        // Create submission record
        $post_id = wp_insert_post(
            [
                'post_type'     => Submission_CPT::POST_TYPE,
                'post_title'    => sanitize_text_field( $artwork_title ),
                'post_status'   => 'private',
                'post_author'   => $user->ID,
            ],
            true
        );
        if( is_wp_error($post_id) ) {
            @unlink($dest_path);
            wp_send_json_error(['message' => __('Could not save submission record.', 'urban-canvas')], 500);
        }

        $meta = [
            '_uc_artist_name'   => $artist_name,
            '_uc_artist_bio'    => $artist_bio,
            '_uc_artwork_title' => $artwork_title,
            '_uc_artwork_desc'  => $artwork_desc,
            '_uc_file_path'     => $dest_path,
            '_uc_original_name' => sanitize_file_name( $_FILES['artwork_file']['name'] ?? '' ),
            '_uc_file_mime'     => $validation['mime'],
            '_uc_submit_ip'     => sanitize_text_field( wp_unslash($_SERVER['REMOTE_ADDR'] ?? '') ),
            '_uc_status'        => 'pending_review', 
        ];
        foreach ( $meta as $key => $value ) {
            update_post_meta($post_id, $key, $value);
        }

        // Increment rate counter.
        set_transient($rate_key, $submissions + 1, DAY_IN_SECONDS );

        Audit_Monitor::logs(
            'submission_ok',
            sprintf('User $%d submitted "%s" (post $%d).', $user->ID, $artwork_title, $post_id)
        );

        wp_send_json_success(
            [
                'message'       => __('Your submission has been recieved! We\'ll be in touch soon.', 'urban-canvas'),
                'submission_id' => $post_id,
            ]
        );
    }

    // Private Storage
    /**
     * Return (and create) a private directory outside the web root for file storage.
     * 
     * Stored at: {WP_CONTENT_DIR}/uc-private-submissions/
     * This directory is NOT inside /uploads/ so web servers never serve it directly.
     * 
     * @return string Absolute path (no trailing slash). 
     */
    
}