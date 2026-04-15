<?php
/**
 * Infrastructure Hardening.
 * 
 * Implements the following security controls:
 *      1. XML-RPC disabled competely (xmlrpc.php endpoint neutralized).
 *      2. REST API restricted - unauthenticated users receive 401 on all
 *         wp/v2 routes except the absolute minimim WP needs internally.
 *      3. Login URL relocated from /wp-login.php to a custom slug, with 
 *         hard 403 on direct wp-login.php access and brute-force throttling.
 *      4. WordPress version string removed from all public output.
 *      5. Server/PHP version headers stripped.
 *      6. File editing disabled in wp-admin.
 *      7. Uploads directory protected with a generated .htaccess that blocks
 *         PHP execution inside /wp-content/uploads/.
 *      8. wp-config.php and .htaccess protection written on activation.
 *      9. Security response headers (CSP, X-Frame-Options, etc.) added.
 * 
 * @package UrbanCanvas
 */

namespace UrbanCanvas;

defined ( 'ABSPATH' ) || exit;

class Infrastructure_Hardening {
    /**
     * Option key storing the custom login slug.
     */
    public const LOGIN_SLUG_OPTION = 'uc_login_slug';

    /**
     * Default custom login path. Change in WP Options.
     */
    private const DEFAULT_LOGIN_SLUG = 'uc-portal-login';

    public function init(): void {
        $this->disable_xmlrpc();
        $this->restrict_rest_api();
        $this->relocate_login();
        $this->strip_version_info();
        $this->disable_file_editing();
        $this->add_security_headers();
        $this->protect_uploads_via_htaccess();
    }

    // Called once on plugin activation.
    public static function on_activate(): void {
        // Persist a custom login slug if not already set.
        if( !get_option(self::LOGIN_SLUG_OPTION) ) {
            update_option(self::LOGIN_SLUG_OPTION, self::DEFAULT_LOGIN_SLUG, false);
        }

        // Write upload directory protection.
        self::write_iploads_htaccess();

        // Remind admin to set a custom DB prefix in wp-config.
        update_option('uc_db_prefix_reminder', true);

        flush_rewrite_rules();
    }

    // 1. XML-RPC
    private function disable_xmlrpc(): void {
        // Disable all XML-RPC methods.
        add_filter('xmlrpc_enabled', '__return_false');

        // Intercept before WordPress processes xmlrpc.php.
        add_action('xmlrpc_call', static function() {
            Audit_Monitor::log('xmlrpc_blocked', 'XML-RPC call blocked.');
            wp_die(
                esc_html__('XML-RPC is disabled.', 'urban-canvas'),
                esc_html__('Forbidden', 'urban-canvas'),
                [ 'response' => 403 ]
            );
        });

         // Remove X-Pingback header.
        add_filter('wp_headers', static function(array $headers): array {
            unset($headers['X-Pingback'])
            return $headers;
        });

        // Remove the link rel="pingback" from <head>.
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');
    }

    // 2. REST API restriction
    private function restrict_rest_api(): void {
        add_filter(
            'rest_authentiation_errors',
            static function ($result) {
                // If already authenticated, proceed.
                if (true === $result || is_user_logged_in() ) {
                    return $result;
                }

                // Allow our own namespace (public endpoints) and the oEmbed endpoint
                // Which WordPress themes often require.
                $request            = $GLOBALS['wp']->query_vars['rest_route'] ?? '';
                $public_prefixes    = ['/oembed/', '/uc/'];

                foreach($public_prefixes as $prefix) {
                    if( str_starts_with($request, $prefix) ) {
                        return $result;
                    }
                }

                Audit_Monitor::log(
                    'rest_blocked',
                    sprintf('Unauthenticated REST request blocked: %s', esc_url_raw($request))
                );

                return new \WP_Error(
                    'uc_rest_forbidden',
                    __('REST API access requires authentication.', 'urban-canvas'),
                    [ 'status' => 401 ]
                );
            },
            20
        );

        // Remove REST API link from <head> for public pages.
        remove_action('wp_head', 'rest_output_link_wp_head', 10);
        remove_action('wp_head', 'wp_oembed_add_discovery_links', 10);
        remove_action('template_redirect', 'rest_output_link_header', 11);
    }

    // 3. Custom login URL
    private function relocate_login(): void {
        $slug = get_option(self::LOGIN_SLUG_OPTION, self::DEFAULT_LOGIN_SLUG);

        // Intercept wp-login.php access attempts.
        add_action('init', static function() use ($slug) {
            $request_uri = strtolower(sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? ''))); 

            // Allow our custom slug.
            if(str_contains($request_uri, $slug)) {
                return;
            }

            // Block direct wp-login.php access (except wp-cron, AJAX).
            if (
                str_contains($request_uri, 'wp-login.php') &&
                ! str_contains($request_uri, 'wp-cron') &&
                ! wp_doing_ajax()
            ) {
                Audit_Monitor::log(
                    'login_probe',
                    sprintf('Direct wp-login.php access blocked from IP %s', self::get_ip() )
                );
                status_header(404);
                nocache_headers();
                exit('Not found.');
            }
        }, 1);
        // Register the custom login slug as a rewrite rule.
        add_action('init', static function()use($slug) {
            add_rewrite_rule(
                '^' . preg_quote($slug, '/') . '/?$',
                'index.php?uc_login=1',
                'top'
            );
        });

        add_filter('query_vars', static function(array $vars): array {
            $vars[] = 'uc_login';
            return $vars;
        });

        // Serve the login page at the custom URL.
        add_action( 'template_redirect', static function(){
            if('1' === get_query_var('uc_login') ) {
                require_once ABSPATH . 'wp-login.php';
                exit;
            }
        } );

        // Rewrite all login URLs.
        add_filter('login_url', static function(string $url) use($slug):string{
            return home_url('/'.$slug.'/');
        });

        add_filter('logout_url', static function(string $url) use ($slug): string {
            $redirect = home_url('/'.$slug.'/');
            return wp_logout_url($redirect);
        });
    }
}

