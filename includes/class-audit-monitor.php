<?php
/**
 * Audit & Integrity Monitor.
 *
 * Provides:
 *   1. Structured audit log stored in a custom DB table (uc_audit_log).
 *   2. Failed login tracking with configurable lockout.
 *   3. File integrity baseline + change detection for core WP files.
 *   4. Admin email alerts for critical events.
 *   5. Log pruning to keep the table lean.
 *
 * @package UrbanCanvas
 */

namespace UrbanCanvas;

defined( 'ABSPATH' ) || exit;

class Audit_Monitor {

	/** Events that trigger an immediate admin alert email. */
	private const ALERT_EVENTS = [
		'blocked_upload',
		'lockout',
		'file_change_detected',
		'login_probe',
	];

	/** Max failed logins before temporary lockout (per IP). */
	private const LOCKOUT_THRESHOLD = 5;

	/** Lockout duration in seconds. */
	private const LOCKOUT_DURATION = 900; // 15 min.

	/** Option key for the file integrity baseline. */
	private const BASELINE_OPTION = 'uc_integrity_baseline';

	/** Maximum log rows to retain. */
	private const MAX_LOG_ROWS = 10000;

	public function init(): void {
		$this->track_failed_logins();
		$this->schedule_integrity_scan();
		add_action( 'uc_integrity_scan',  [ $this, 'run_integrity_scan'  ] );
		add_action( 'uc_prune_audit_log', [ $this, 'prune_log'           ] );

		// Schedule log pruning weekly if not already scheduled.
		if ( ! wp_next_scheduled( 'uc_prune_audit_log' ) ) {
			wp_schedule_event( time(), 'weekly', 'uc_prune_audit_log' );
		}
	}

	// ── DB Table ──────────────────────────────────────────────────────────────

	/** Create the audit log table on plugin activation. */
	public static function create_tables(): void {
		global $wpdb;

		$table   = $wpdb->prefix . 'uc_audit_log';
		$charset = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$table} (
			id          BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			event_type  VARCHAR(64)         NOT NULL,
			message     TEXT                NOT NULL,
			ip_address  VARCHAR(45)         NOT NULL DEFAULT '',
			user_id     BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
			created_at  DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY idx_event_type (event_type),
			KEY idx_created_at (created_at),
			KEY idx_ip_address (ip_address)
		) {$charset};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	// ── Logging ───────────────────────────────────────────────────────────────

	/**
	 * Write a structured audit log entry.
	 *
	 * @param  string $event_type  Short snake_case event identifier.
	 * @param  string $message     Human-readable description.
	 * @param  bool   $force_alert Override and always send alert email.
	 */
	public static function log( string $event_type, string $message, bool $force_alert = false ): void {
		global $wpdb;

		$ip      = self::get_ip();
		$user_id = is_user_logged_in() ? get_current_user_id() : 0;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$wpdb->prefix . 'uc_audit_log',
			[
				'event_type' => sanitize_key( $event_type ),
				'message'    => sanitize_textarea_field( $message ),
				'ip_address' => $ip,
				'user_id'    => $user_id,
				'created_at' => current_time( 'mysql', true ),
			],
			[ '%s', '%s', '%s', '%d', '%s' ]
		);

		// Send admin email for high-severity events.
		if ( $force_alert || in_array( $event_type, self::ALERT_EVENTS, true ) ) {
			self::send_alert( $event_type, $message, $ip );
		}
	}

	// ── Failed Login Tracking ─────────────────────────────────────────────────

	private function track_failed_logins(): void {
		add_action( 'wp_login_failed', [ $this, 'on_login_failed' ] );
		add_action( 'wp_authenticate',  [ $this, 'check_lockout'  ], 1, 1 );
		add_action( 'wp_login',         [ $this, 'on_login_ok'    ], 10, 2 );
	}

	public function on_login_failed( string $username ): void {
		$ip       = self::get_ip();
		$key      = 'uc_fails_' . md5( $ip );
		$attempts = (int) get_transient( $key );
		$attempts++;

		set_transient( $key, $attempts, self::LOCKOUT_DURATION );

		self::log(
			'login_failed',
			sprintf( 'Failed login for username "%s" (attempt %d).', sanitize_user( $username ), $attempts )
		);

		if ( $attempts >= self::LOCKOUT_THRESHOLD ) {
			set_transient( 'uc_locked_' . md5( $ip ), true, self::LOCKOUT_DURATION );
			self::log(
				'lockout',
				sprintf( 'IP %s locked out after %d failed login attempts.', $ip, $attempts ),
				true
			);
		}
	}

	public function check_lockout( ?string $username ): void {
		$ip = self::get_ip();
		if ( get_transient( 'uc_locked_' . md5( $ip ) ) ) {
			self::log(
				'lockout_blocked',
				sprintf( 'Login attempt blocked: IP %s is currently locked out.', $ip )
			);
			wp_die(
				esc_html__(
					'Too many failed login attempts. Please wait 15 minutes before trying again.',
					'urban-canvas'
				),
				esc_html__( 'Access Temporarily Blocked', 'urban-canvas' ),
				[ 'response' => 429 ]
			);
		}
	}

	public function on_login_ok( string $username, \WP_User $user ): void {
		$ip = self::get_ip();
		delete_transient( 'uc_fails_'  . md5( $ip ) );
		delete_transient( 'uc_locked_' . md5( $ip ) );
		self::log( 'login_ok', sprintf( 'Successful login for user "%s".', $username ) );
	}

	// ── File Integrity Monitoring ─────────────────────────────────────────────

	private function schedule_integrity_scan(): void {
		if ( ! wp_next_scheduled( 'uc_integrity_scan' ) ) {
			wp_schedule_event( time(), 'daily', 'uc_integrity_scan' );
		}
	}

	/**
	 * Build or compare a SHA-256 hash baseline of critical WP core files.
	 * Only monitors a curated set — scanning everything would be too slow.
	 */
	public function run_integrity_scan(): void {
		$critical_files = [
			ABSPATH . 'wp-login.php',
			ABSPATH . 'wp-config.php',
			ABSPATH . 'index.php',
			ABSPATH . 'wp-settings.php',
			ABSPATH . 'wp-includes/class-wp.php',
			ABSPATH . 'wp-includes/functions.php',
			ABSPATH . 'wp-admin/index.php',
		];

		$current = [];
		foreach ( $critical_files as $file ) {
			if ( file_exists( $file ) ) {
				$current[ $file ] = hash_file( 'sha256', $file );
			}
		}

		$baseline = get_option( self::BASELINE_OPTION );

		if ( false === $baseline ) {
			// First run — store baseline.
			update_option( self::BASELINE_OPTION, $current, false );
			self::log( 'integrity_baseline', sprintf( 'File integrity baseline created for %d files.', count( $current ) ) );
			return;
		}

		$changed = [];
		foreach ( $current as $file => $hash ) {
			if ( isset( $baseline[ $file ] ) && $baseline[ $file ] !== $hash ) {
				$changed[] = $file;
			}
		}

		if ( ! empty( $changed ) ) {
			self::log(
				'file_change_detected',
				sprintf(
					'File change detected in %d monitored files: %s',
					count( $changed ),
					implode( ', ', array_map( 'basename', $changed ) )
				),
				true
			);
		} else {
			self::log( 'integrity_ok', 'File integrity scan passed — no changes detected.' );
		}

		// Update baseline after scan.
		update_option( self::BASELINE_OPTION, $current, false );
	}

	/** Rebuild baseline manually (e.g., after an intentional WP core update). */
	public static function rebuild_baseline(): void {
		delete_option( self::BASELINE_OPTION );
	}

	// ── Alerting ──────────────────────────────────────────────────────────────

	private static function send_alert( string $event_type, string $message, string $ip ): void {
		$to      = get_option( 'admin_email' );
		$subject = sprintf(
			/* translators: %s: event type */
			__( '[Urban Canvas Security] Alert: %s', 'urban-canvas' ),
			strtoupper( str_replace( '_', ' ', $event_type ) )
		);

		$body = sprintf(
			"Urban Canvas Security Alert\n\n" .
			"Event:   %s\n" .
			"Message: %s\n" .
			"IP:      %s\n" .
			"Time:    %s\n\n" .
			"Review the full audit log in WP Admin → Urban Canvas → Audit Log.",
			$event_type,
			$message,
			$ip,
			current_time( 'Y-m-d H:i:s T' )
		);

		wp_mail( $to, $subject, $body );
	}

	// ── Log Retrieval (for admin dashboard) ──────────────────────────────────

	/**
	 * Retrieve recent log entries.
	 *
	 * @param  int    $limit      Number of rows.
	 * @param  string $event_type Optional filter.
	 * @return array
	 */
	public static function get_logs( int $limit = 100, string $event_type = '' ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'uc_audit_log';

		if ( $event_type ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			return $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM {$table} WHERE event_type = %s ORDER BY id DESC LIMIT %d",
					$event_type,
					$limit
				)
			);
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", $limit )
		);
	}

	/** Prune oldest rows beyond MAX_LOG_ROWS. */
	public function prune_log(): void {
		global $wpdb;
		$table = $wpdb->prefix . 'uc_audit_log';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE id NOT IN (SELECT id FROM (SELECT id FROM {$table} ORDER BY id DESC LIMIT %d) AS t)",
				self::MAX_LOG_ROWS
			)
		);
	}

	// ── Helpers ───────────────────────────────────────────────────────────────

	private static function get_ip(): string {
		$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0' ) );
		if ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$parts = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
			$ip    = trim( $parts[0] );
		}
		return filter_var( $ip, FILTER_VALIDATE_IP ) ?: '0.0.0.0';
	}
}
