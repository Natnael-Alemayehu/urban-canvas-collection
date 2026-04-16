<?php
/**
 * Submission Custom Post Type.
 * 
 * Registers the `uc_sumbmission` CPT and associated meta fields for:
 *      - Artist name and bio (sanitized text).
 *      - Artwork title and description.
 *      - Submitted file path (private, non-web-accessible directory).
 *      - Submission status: pending_review, approved, rejected.
 *      - Submission metadata: IP, timestamp, file MIME, original filename.
 * 
 * @package UrbanCanvas
 */

namespace UrbanCanvas;

defined ( 'ABSPATH' ) || exit;

class Submission_CPT {
    public const POST_TYPE = 'uc_submission';

    public const STATUSES = [
        'pending_review'        => 'Pending Review',
        'approved'              => 'Approved',
        'rejected'              => 'Rejected.'
    ];

    public function init(): void{
        add_action('init', [$this, 'register_cpt']);
        add_action('init', [$this, 'register_meta']);
    }

    public function register_cpt(): void {
        register_post_type(
            self::POST_TYPE, 
            [
                'labels' => [
                    'name'              => __('Submissions', 'urban-canvas'),
                    'singular_name'     => __('Submission', 'urban-canvas'),
                    'menu_name'         => __('Submissions', 'urban-canvas'),
                    'all_items'         => __('All Submissions', 'urban-canvas'),
                    'edit_items'        => __('Review Submissions', 'urban-canvas'),
                    'not_found'         => __('No Submissions found.', 'urban-canvas'),
                ],
                'public'                => false,
                'show_ui'               => true,
                'show_in_menu'          => false,   // Shown under our custom menu. 
                'show_in_rest'          => false,   // No REST exposure.
                'supports'              => ['title', 'author'],
                'capability_type'       => 'post',
                'map_meta_cap'          => true,
                'has_archive'           => false,
                'rewrite'               => false,
                'exclude_from_search'   => true,
            ]
        );
    }

    public function register_meta(): void {
        $text_meta = [
            '_uc_artist_name'       => 'Artist display name.',
            '_uc_artist_bio'        => 'Short artist biography',
            '_uc_artwork_title'     => 'Artwork title.',
            '_uc_artwork_desc'      => 'Artwork descriptio',
            '_uc_file_path'         => 'Absolute path to stored artwork file.',
            '_uc_original_name'     => 'Original filename supplied by the artist.',
            '_uc_file_mime'         => 'Detected MIME type of the artwork file.',
            '_uc_submit_ip'         => 'IP address at time of submission.',
            '_uc_status'            => 'Submission review status.', 
            '_uc_reviewer_notes'    => 'Internal notes from the reviewer.',
        ];

        foreach( $text_meta as $key => $description ) {
            register_post_meta(
                self::POST_TYPE,
                $key,
                [
                    'type'              => 'string',
                    'description'       => $description,
                    'single'            => true,
                    'default'           => '',
                    'show_in_rest'      => false,
                    'sanitize_callback' => 'sanitize_textarea_field',
                    'auth_callback'     => static fn() => current_user_can('edit_posts'),
                ]
            );
        }
    }
}