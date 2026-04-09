<?php
/**
 * Plugin Name: Urban Collective - Hardened Submission Portal
 * Plugin URI: https://https://github.com/Natnael-Alemayehu/urban-canvas-collection
 * Description: Complete secutiry reconstruction for the urban Canvas Collective art submission portal.
 *              Covers hardend, zero-trust roles, audit monitoring, and a font-end submission workflow.
 * Version: 1.0.0
 * Author: Nate
 * 
 * @ package UrbanCanvas; 
 */

namespace UrbanCanvas;

defined( 'ABSPATH' ) || exit;

// ── Constants ────────────────────────────────────────────────────────────────
define( 'UC_VERSION',     '1.0.0' );
define( 'UC_PLUGIN_DIR',  plugin_dir_path( __FILE__ ) );
define( 'UC_PLUGIN_URL',  plugin_dir_url( __FILE__ ) );
define( 'UC_PLUGIN_FILE', __FILE__ );
define( 'UC_MIN_PHP',     '8.1' );

// ── PHP version gate ──────────────────────────────────────────────────────────
if ( version_compare( PHP_VERSION, UC_MIN_PHP, '<' ) ) {
	add_action(
		'admin_notices',
		static function () {
			printf(
				'<div class="notice notice-error"><p>%s</p></div>',
				esc_html(
					sprintf(
						/* translators: %s: minimum PHP version */
						__( 'Urban Canvas Security requires PHP %s or higher.', 'urban-canvas' ),
						UC_MIN_PHP
					)
				)
			);
		}
	);
	return;
}

// ── Includes ──────────────────────────────────────────────────────────────────
$uc_files = [
	'includes/class-artist-role.php',
	'includes/class-file-validator.php',
	'includes/class-exif-scrubber.php',
	'includes/class-infrastructure-hardening.php',
	'includes/class-audit-monitor.php',
	'includes/class-submission-handler.php',
	'includes/class-submission-cpt.php',
	'includes/class-admin-dashboard.php',
];

foreach ( $uc_files as $uc_file ) {
	require_once UC_PLUGIN_DIR . $uc_file;
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────
add_action( 'plugins_loaded', static function () {
	( new Infrastructure_Hardening() )->init();
	( new Exif_Scrubber() )->init();
	( new Audit_Monitor() )->init();
	( new Submission_Handler() )->init();
	( new Submission_CPT() )->init();
	( new Admin_Dashboard() )->init();
} );

register_activation_hook(   UC_PLUGIN_FILE, [ 'UrbanCanvas\Artist_Role', 'activate'   ] );
register_deactivation_hook( UC_PLUGIN_FILE, [ 'UrbanCanvas\Artist_Role', 'deactivate' ] );
register_activation_hook(   UC_PLUGIN_FILE, [ 'UrbanCanvas\Audit_Monitor', 'create_tables' ] );
register_activation_hook(   UC_PLUGIN_FILE, [ 'UrbanCanvas\Infrastructure_Hardening', 'on_activate' ] );
