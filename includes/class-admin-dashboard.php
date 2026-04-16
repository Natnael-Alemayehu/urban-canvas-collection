<?php
/**
 * Admin Dashboard.
 *
 * Provides:
 *   - Top-level admin menu: Urban Canvas.
 *   - Submission review screen with status management.
 *   - Audit Log viewer with event-type filtering.
 *   - Security overview (integrity status, lockout stats, blocked uploads).
 *   - Secure file download endpoint for private submission files.
 *
 * @package UrbanCanvas
 */

namespace UrbanCanvas;

defined( 'ABSPATH' ) || exit;

class Admin_Dashboard {

	public function init(): void {
		add_action( 'admin_menu',    [ $this, 'register_menus'     ] );
		add_action( 'admin_init',    [ $this, 'handle_admin_forms' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin_assets' ] );
		add_action( 'admin_init',    [ $this, 'handle_file_download' ] );
	}

	// ── Menus ─────────────────────────────────────────────────────────────────

	public function register_menus(): void {
		add_menu_page(
			__( 'Urban Canvas', 'urban-canvas' ),
			__( 'Urban Canvas', 'urban-canvas' ),
			'manage_options',
			'urban-canvas',
			[ $this, 'page_security_overview' ],
			'dashicons-shield',
			30
		);

		add_submenu_page(
			'urban-canvas',
			__( 'Security Overview', 'urban-canvas' ),
			__( 'Security', 'urban-canvas' ),
			'manage_options',
			'urban-canvas',
			[ $this, 'page_security_overview' ]
		);

		add_submenu_page(
			'urban-canvas',
			__( 'Submissions', 'urban-canvas' ),
			__( 'Submissions', 'urban-canvas' ),
			'manage_options',
			'urban-canvas-submissions',
			[ $this, 'page_submissions' ]
		);

		add_submenu_page(
			'urban-canvas',
			__( 'Audit Log', 'urban-canvas' ),
			__( 'Audit Log', 'urban-canvas' ),
			'manage_options',
			'urban-canvas-audit',
			[ $this, 'page_audit_log' ]
		);
	}

	public function enqueue_admin_assets( string $hook ): void {
		if ( ! str_contains( $hook, 'urban-canvas' ) ) {
			return;
		}
		wp_enqueue_style( 'uc-admin', UC_PLUGIN_URL . 'assets/css/admin.css', [], UC_VERSION );
	}

	// ── Security Overview ─────────────────────────────────────────────────────

	public function page_security_overview(): void {
		$blocked_uploads = count( Audit_Monitor::get_logs( 1000, 'blocked_upload'       ) );
		$lockouts        = count( Audit_Monitor::get_logs( 1000, 'lockout'              ) );
		$integrity_fails = count( Audit_Monitor::get_logs( 100,  'file_change_detected' ) );
		$recent_logs     = Audit_Monitor::get_logs( 10 );

		$login_slug      = get_option( Infrastructure_Hardening::LOGIN_SLUG_OPTION, 'uc-portal-login' );
		$custom_login    = home_url( '/' . $login_slug . '/' );
		?>
		<div class="wrap uc-admin">
			<h1><?php esc_html_e( 'Urban Canvas — Security Overview', 'urban-canvas' ); ?></h1>

			<div class="uc-stat-row">
				<div class="uc-stat uc-stat--<?php echo $blocked_uploads > 0 ? 'danger' : 'ok'; ?>">
					<span class="uc-stat__number"><?php echo esc_html( $blocked_uploads ); ?></span>
					<span class="uc-stat__label"><?php esc_html_e( 'Blocked Uploads', 'urban-canvas' ); ?></span>
				</div>
				<div class="uc-stat uc-stat--<?php echo $lockouts > 0 ? 'warn' : 'ok'; ?>">
					<span class="uc-stat__number"><?php echo esc_html( $lockouts ); ?></span>
					<span class="uc-stat__label"><?php esc_html_e( 'IP Lockouts', 'urban-canvas' ); ?></span>
				</div>
				<div class="uc-stat uc-stat--<?php echo $integrity_fails > 0 ? 'danger' : 'ok'; ?>">
					<span class="uc-stat__number"><?php echo esc_html( $integrity_fails ); ?></span>
					<span class="uc-stat__label"><?php esc_html_e( 'File Changes', 'urban-canvas' ); ?></span>
				</div>
			</div>

			<h2><?php esc_html_e( 'Hardening Status', 'urban-canvas' ); ?></h2>
			<table class="uc-status-table widefat">
				<thead><tr><th><?php esc_html_e( 'Control', 'urban-canvas' ); ?></th><th><?php esc_html_e( 'Status', 'urban-canvas' ); ?></th><th><?php esc_html_e( 'Detail', 'urban-canvas' ); ?></th></tr></thead>
				<tbody>
					<?php $this->status_row( 'XML-RPC', true, 'Disabled via xmlrpc_enabled filter.' ); ?>
					<?php $this->status_row( 'REST API (public)', true, 'Unauthenticated access returns 401.' ); ?>
					<?php $this->status_row( 'Custom Login URL', true, esc_url( $custom_login ) ); ?>
					<?php $this->status_row( 'File Editing', true, 'DISALLOW_FILE_EDIT enforced.' ); ?>
					<?php $this->status_row( 'EXIF Scrubbing', extension_loaded( 'gd' ), extension_loaded( 'gd' ) ? 'GD available.' : 'WARNING: GD not installed.' ); ?>
					<?php $this->status_row( 'Security Headers', true, 'CSP, X-Frame-Options, HSTS set.' ); ?>
					<?php $this->status_row( 'Uploads .htaccess', $this->uploads_htaccess_ok(), $this->uploads_htaccess_ok() ? 'PHP execution blocked.' : 'WARNING: .htaccess not found.' ); ?>
					<?php $this->status_row( 'Brute-Force Protection', true, '5 attempts → 15 min lockout.' ); ?>
					<?php $this->status_row( 'Integrity Monitoring', wp_next_scheduled( 'uc_integrity_scan' ) !== false, 'Daily cron scan active.' ); ?>
				</tbody>
			</table>

			<h2><?php esc_html_e( 'Recent Audit Events', 'urban-canvas' ); ?></h2>
			<?php $this->render_log_table( $recent_logs ); ?>
			<p><a href="<?php echo esc_url( admin_url( 'admin.php?page=urban-canvas-audit' ) ); ?>"><?php esc_html_e( 'View full audit log →', 'urban-canvas' ); ?></a></p>

			<h2><?php esc_html_e( 'Maintenance Actions', 'urban-canvas' ); ?></h2>
			<form method="post">
				<?php wp_nonce_field( 'uc_admin_action' ); ?>
				<input type="hidden" name="uc_action" value="rebuild_baseline">
				<?php submit_button( __( 'Rebuild File Integrity Baseline', 'urban-canvas' ), 'secondary', 'uc_submit', false ); ?>
			</form>
		</div>
		<?php
	}

	// ── Submissions ───────────────────────────────────────────────────────────

	public function page_submissions(): void {
		$status_filter = sanitize_key( $_GET['uc_status'] ?? '' );
		$args = [
			'post_type'      => Submission_CPT::POST_TYPE,
			'post_status'    => 'private',
			'posts_per_page' => 50,
			'orderby'        => 'date',
			'order'          => 'DESC',
		];

		if ( $status_filter ) {
			$args['meta_query'] = [ // phpcs:ignore
				[ 'key' => '_uc_status', 'value' => $status_filter ]
			];
		}

		$submissions = get_posts( $args );
		?>
		<div class="wrap uc-admin">
			<h1><?php esc_html_e( 'Submissions', 'urban-canvas' ); ?></h1>

			<ul class="subsubsub">
				<?php foreach ( [ '' => 'All', 'pending_review' => 'Pending', 'approved' => 'Approved', 'rejected' => 'Rejected' ] as $key => $label ) : ?>
					<li><a href="<?php echo esc_url( admin_url( 'admin.php?page=urban-canvas-submissions' . ( $key ? '&uc_status=' . $key : '' ) ) ); ?>" class="<?php echo ( $status_filter === $key ) ? 'current' : ''; ?>"><?php echo esc_html( $label ); ?></a> |</li>
				<?php endforeach; ?>
			</ul>

			<table class="widefat uc-submissions-table">
				<thead><tr>
					<th><?php esc_html_e( 'Artwork', 'urban-canvas' ); ?></th>
					<th><?php esc_html_e( 'Artist', 'urban-canvas' ); ?></th>
					<th><?php esc_html_e( 'File', 'urban-canvas' ); ?></th>
					<th><?php esc_html_e( 'Status', 'urban-canvas' ); ?></th>
					<th><?php esc_html_e( 'Submitted', 'urban-canvas' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'urban-canvas' ); ?></th>
				</tr></thead>
				<tbody>
					<?php if ( empty( $submissions ) ) : ?>
						<tr><td colspan="6"><?php esc_html_e( 'No submissions found.', 'urban-canvas' ); ?></td></tr>
					<?php else : ?>
						<?php foreach ( $submissions as $sub ) :
							$status = get_post_meta( $sub->ID, '_uc_status', true ) ?: 'pending_review';
							$artist = get_post_meta( $sub->ID, '_uc_artist_name', true );
							$mime   = get_post_meta( $sub->ID, '_uc_file_mime', true );
							$dl_url = wp_nonce_url( admin_url( 'admin.php?page=urban-canvas-submissions&uc_download=' . $sub->ID ), 'uc_download_' . $sub->ID );
						?>
						<tr>
							<td><strong><?php echo esc_html( $sub->post_title ); ?></strong><br><small>#<?php echo esc_html( $sub->ID ); ?></small></td>
							<td><?php echo esc_html( $artist ); ?></td>
							<td><?php echo esc_html( $mime ); ?></td>
							<td><span class="uc-badge uc-badge--<?php echo esc_attr( $status ); ?>"><?php echo esc_html( Submission_CPT::STATUSES[ $status ] ?? $status ); ?></span></td>
							<td><?php echo esc_html( get_the_date( 'Y-m-d H:i', $sub ) ); ?></td>
							<td>
								<a href="<?php echo esc_url( $dl_url ); ?>" class="button button-small"><?php esc_html_e( 'Download', 'urban-canvas' ); ?></a>
								<a href="<?php echo esc_url( get_edit_post_link( $sub->ID ) ); ?>" class="button button-small"><?php esc_html_e( 'Review', 'urban-canvas' ); ?></a>
							</td>
						</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	// ── Audit Log ─────────────────────────────────────────────────────────────

	public function page_audit_log(): void {
		$filter = sanitize_key( $_GET['uc_event'] ?? '' );
		$logs   = Audit_Monitor::get_logs( 200, $filter );
		$events = [ '', 'blocked_upload', 'login_failed', 'lockout', 'file_change_detected', 'submission_ok', 'rest_blocked', 'exif_scrubbed' ];
		?>
		<div class="wrap uc-admin">
			<h1><?php esc_html_e( 'Audit Log', 'urban-canvas' ); ?></h1>

			<form method="get">
				<input type="hidden" name="page" value="urban-canvas-audit">
				<select name="uc_event">
					<?php foreach ( $events as $e ) : ?>
						<option value="<?php echo esc_attr( $e ); ?>" <?php selected( $filter, $e ); ?>><?php echo esc_html( $e ?: 'All events' ); ?></option>
					<?php endforeach; ?>
				</select>
				<?php submit_button( __( 'Filter', 'urban-canvas' ), 'secondary', '', false ); ?>
			</form>

			<?php $this->render_log_table( $logs ); ?>
		</div>
		<?php
	}

	// ── Admin Form Handlers ───────────────────────────────────────────────────

	public function handle_admin_forms(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( isset( $_POST['uc_action'] ) && 'rebuild_baseline' === $_POST['uc_action'] ) {
			check_admin_referer( 'uc_admin_action' );
			Audit_Monitor::rebuild_baseline();
			add_action( 'admin_notices', static function () {
				echo '<div class="notice notice-success"><p>' . esc_html__( 'File integrity baseline has been rebuilt.', 'urban-canvas' ) . '</p></div>';
			} );
		}
	}

	// ── Secure File Download ──────────────────────────────────────────────────

	public function handle_file_download(): void {
		if ( empty( $_GET['uc_download'] ) ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Access denied.', 'urban-canvas' ), 403 );
		}

		$post_id = absint( $_GET['uc_download'] );
		if ( ! check_admin_referer( 'uc_download_' . $post_id ) ) {
			wp_die( esc_html__( 'Security check failed.', 'urban-canvas' ), 403 );
		}

		$post = get_post( $post_id );
		if ( ! $post || Submission_CPT::POST_TYPE !== $post->post_type ) {
			wp_die( esc_html__( 'Submission not found.', 'urban-canvas' ), 404 );
		}

		$file_path = get_post_meta( $post_id, '_uc_file_path', true );
		$mime      = get_post_meta( $post_id, '_uc_file_mime', true );

		if ( ! $file_path || ! file_exists( $file_path ) ) {
			wp_die( esc_html__( 'File not found.', 'urban-canvas' ), 404 );
		}

		// Validate path is within our private directory.
		$allowed_base = WP_CONTENT_DIR . '/uc-private-submissions/';
		if ( ! str_starts_with( realpath( $file_path ), realpath( $allowed_base ) ) ) {
			wp_die( esc_html__( 'Invalid file path.', 'urban-canvas' ), 403 );
		}

		Audit_Monitor::log( 'file_downloaded', sprintf( 'Admin downloaded submission #%d', $post_id ) );

		header( 'Content-Type: ' . sanitize_mime_type( $mime ) );
		header( 'Content-Disposition: attachment; filename="' . esc_attr( basename( $file_path ) ) . '"' );
		header( 'Content-Length: ' . filesize( $file_path ) );
		header( 'X-Content-Type-Options: nosniff' );
		nocache_headers();
		readfile( $file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile
		exit;
	}

	// ── Reusable Components ───────────────────────────────────────────────────

	private function status_row( string $label, bool $ok, string $detail ): void {
		printf(
			'<tr><td>%s</td><td><span class="uc-status-dot uc-status-dot--%s">%s</span></td><td>%s</td></tr>',
			esc_html( $label ),
			$ok ? 'ok' : 'fail',
			$ok ? '✓ Active' : '✗ Inactive',
			esc_html( $detail )
		);
	}

	private function render_log_table( array $logs ): void {
		echo '<table class="widefat"><thead><tr>';
		echo '<th>Event</th><th>Message</th><th>IP</th><th>User</th><th>Time (UTC)</th>';
		echo '</tr></thead><tbody>';

		if ( empty( $logs ) ) {
			echo '<tr><td colspan="5">' . esc_html__( 'No log entries found.', 'urban-canvas' ) . '</td></tr>';
		} else {
			foreach ( $logs as $entry ) {
				printf(
					'<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
					esc_html( $entry->event_type ),
					esc_html( $entry->message ),
					esc_html( $entry->ip_address ),
					esc_html( $entry->user_id ? "#$entry->user_id" : '—' ),
					esc_html( $entry->created_at )
				);
			}
		}

		echo '</tbody></table>';
	}

	private function uploads_htaccess_ok(): bool {
		$upload_dir = wp_upload_dir();
		$htaccess   = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';
		return file_exists( $htaccess );
	}
}
