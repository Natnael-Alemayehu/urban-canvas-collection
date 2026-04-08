<?php
/**
 * Artist Role - Zero-Trust User Management.
 * 
 * Creates a strictly partitioned "Artist" role. Members can:
 *  - Submit artwork via the front-end portal only.
 *  - View their own published/pending submissions.
 * 
 * Artists CANNOT:
 *  - Access wp-admin (hard redirect on admin_init).
 *  - Access the filesystem, plugins, themes, users, settings.
 *  - Edit or delete other users' content.
 * 
 * @package UrbanCanvas
 */

namespace UrbanCanvas;

defined( 'ABSPATH' ) || exit;