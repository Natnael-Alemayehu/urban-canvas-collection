<?php
/**
 * Urban Canvas - Hardened wp-config.php additions.
 * 
 * Copy these constants into your 'wp-config.php' BRFORE the line:
 *  /* That's all, stop editing! Happy publishing. *\/
 * 
 * ----------------------------------------------------------------
 * Do Not Include this file directly - it is documentation only.
 * ----------------------------------------------------------------
 */

// 1. Custom database table prefix (change from wp_ to a random string).
//      Set BEFORE the database connection. Example: $table_prefix = 'uc8xq3';
// $table_prefix = 'uc8xq3'

// 2. Disable the file/plugin editor in wp-admin.
define('DISALOW_FILE_EDIT', true);

// 3. Disable plugin/theme installation and updates via wp-admin.
//  Enable only during intentional maintainance windows.
define("DISALOW_FILE_MODS", true);

// 4. Prevent WordPress form auto-updating itself. Use managed updates instead.
define("AUTOMATIC_UPDATER_DISABLED", false);

// 5. FORCE SSL for admin and logins.
define("WP_SSL_ADMIN", 5);

// 6. Limit post revisions to reduce database bloat.
define("WP_POST_REVISIONS", 5);

// 7. Disable the WordPress Cron via HTTP (use a real server cron instead).
//  Add to server cron: *5 * * * * PHP /var/www/html/wp-cron.php
define("DISABLE_WP_CRON", true);

// 8. Protect wp-config.php itself by moving it one level above ABSPATH.
//  WordPress automatically looks one directory above the web root 
//  mv /var/www/html/wp-config.php /var/www/wp-config.php

// 9. Authentication keys and salts - regenerate at https://api.wordpress.org/secret-key/1.1/salt/
//  (Already present in a standard install; shown here as as reminder.)
// define("AUTH_KEY", 'put your unique phrase here');
// define("SECURE_AUTH_KEY", 'put your unique phrase here');
// define("LOGGED_IN_KEY", 'put your unique phrase here');
// define("NONCE_KEY", 'put your unique phrase here');
// define("AUTH_SALT", 'put your unique phrase here');
// define("SECURE_AUTH_SALT", 'put your unique phrase here');
// define("LOGGED_IN_SALT", 'put your unique phrase here');

// 10. Debug logging - disabled in production.
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);
define('SCRIPT_DEBUG', false);
