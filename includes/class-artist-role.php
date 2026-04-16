<?php
/**
 * Artist Role – Zero-Trust User Management.
 *
 * Creates a strictly partitioned "Artist" role. Members can:
 *   - Submit artwork via the front-end portal only.
 *   - View their own published/pending submissions.
 *
 * Artists CANNOT:
 *   - Access wp-admin (hard redirect on admin_init).
 *   - Access the filesystem, plugins, themes, users, settings.
 *   - Edit or delete other users' content.
 *
 * @package UrbanCanvas
 */

namespace UrbanCanvas;

defined( 'ABSPATH' ) || exit;

class Artist_Role {

	public const ROLE_SLUG = 'uc_artist';

	/** Called on plugin activation. */
	public static function activate(): void {
		self::register_role();
		flush_rewrite_rules();
	}

	/** Called on plugin deactivation. */
	public static function deactivate(): void {
		remove_role( self::ROLE_SLUG );
	}

	/**
	 * Register the role with minimal capabilities.
	 * We deliberately grant zero standard WP caps and rely solely
	 * on our own custom capability for the front-end.
	 */
	public static function register_role(): void {
		remove_role( self::ROLE_SLUG ); // idempotent re-register.

		add_role(
			self::ROLE_SLUG,
			__( 'Artist', 'urban-canvas' ),
			[
				'read'              => true,         // Bare minimum WP requires.
				'uc_submit_artwork' => true,          // Our custom capability.
				'upload_files'      => false,         // Only via our validated handler.
			]
		);
	}

	/**
	 * Redirect Artist users away from wp-admin entirely.
	 * Hook: admin_init (fires before any admin page renders).
	 */
	public static function lock_dashboard(): void {
		add_action( 'admin_init', static function () {
			if ( ! is_user_logged_in() ) {
				return;
			}

			$user = wp_get_current_user();
			if ( ! in_array( self::ROLE_SLUG, (array) $user->roles, true ) ) {
				return;
			}

			// Allow AJAX calls used internally.
			if ( wp_doing_ajax() ) {
				return;
			}

			wp_safe_redirect( home_url( '/submit/' ) );
			exit;
		} );

		// Remove the admin bar for Artists entirely.
		add_filter( 'show_admin_bar', static function ( bool $show ): bool {
			if ( is_user_logged_in() ) {
				$user = wp_get_current_user();
				if ( in_array( self::ROLE_SLUG, (array) $user->roles, true ) ) {
					return false;
				}
			}
			return $show;
		} );
	}

	/**
	 * Block Artists from accessing media library frames directly.
	 * They may only upload through our submission handler.
	 */
	public static function block_media_library(): void {
		add_action( 'admin_init', static function () {
			if ( ! is_user_logged_in() ) {
				return;
			}
			$user = wp_get_current_user();
			if ( in_array( self::ROLE_SLUG, (array) $user->roles, true ) ) {
				// Remove upload_files to kill media library access.
				$user->remove_cap( 'upload_files' );
			}
		} );
	}

	/**
	 * Prevent Artists from editing/deleting their published posts
	 * via any WP native interface — only the front-end portal is allowed.
	 */
	public static function map_meta_caps( array $caps, string $cap, int $user_id, array $args ): array {
		$restricted_caps = [
			'edit_post',
			'delete_post',
			'edit_published_posts',
			'delete_published_posts',
		];

		if ( ! in_array( $cap, $restricted_caps, true ) ) {
			return $caps;
		}

		$user = get_userdata( $user_id );
		if ( $user && in_array( self::ROLE_SLUG, (array) $user->roles, true ) ) {
			// Return 'do_not_allow' to unconditionally block the capability.
			return [ 'do_not_allow' ];
		}

		return $caps;
	}
}
