<?php
/**
 * Submission Form Template.
 *
 * Rendered via the [uc_submission_form] shortcode.
 * All output is escaped; the form submits via AJAX.
 *
 * @package UrbanCanvas
 */

defined( 'ABSPATH' ) || exit;

$user = wp_get_current_user();
?>
<div class="uc-submission-portal" id="uc-portal">

	<div class="uc-portal__header">
		<h2 class="uc-portal__title"><?php esc_html_e( 'Submit Your Artwork', 'urban-canvas' ); ?></h2>
		<p class="uc-portal__subtitle"><?php esc_html_e( 'Share your mural work with the Urban Canvas Collective. Accepted formats: JPG, PNG, PDF (max 10 MB).', 'urban-canvas' ); ?></p>
	</div>

	<div class="uc-portal__notice" id="uc-notice" role="alert" aria-live="polite" hidden></div>

	<form class="uc-form" id="uc-submission-form" novalidate>

		<fieldset class="uc-fieldset">
			<legend class="uc-legend"><?php esc_html_e( 'About You', 'urban-canvas' ); ?></legend>

			<div class="uc-field">
				<label class="uc-label" for="uc-artist-name">
					<?php esc_html_e( 'Your Name', 'urban-canvas' ); ?>
					<span class="uc-required" aria-hidden="true">*</span>
				</label>
				<input
					class="uc-input"
					type="text"
					id="uc-artist-name"
					name="artist_name"
					value="<?php echo esc_attr( $user->display_name ); ?>"
					maxlength="100"
					required
					autocomplete="name"
				>
			</div>

			<div class="uc-field">
				<label class="uc-label" for="uc-artist-bio">
					<?php esc_html_e( 'Short Bio (optional)', 'urban-canvas' ); ?>
				</label>
				<textarea
					class="uc-textarea"
					id="uc-artist-bio"
					name="artist_bio"
					rows="3"
					maxlength="500"
					placeholder="<?php esc_attr_e( 'Tell us a little about yourself and your practice…', 'urban-canvas' ); ?>"
				></textarea>
			</div>
		</fieldset>

		<fieldset class="uc-fieldset">
			<legend class="uc-legend"><?php esc_html_e( 'Your Artwork', 'urban-canvas' ); ?></legend>

			<div class="uc-field">
				<label class="uc-label" for="uc-artwork-title">
					<?php esc_html_e( 'Artwork Title', 'urban-canvas' ); ?>
					<span class="uc-required" aria-hidden="true">*</span>
				</label>
				<input
					class="uc-input"
					type="text"
					id="uc-artwork-title"
					name="artwork_title"
					maxlength="200"
					required
					autocomplete="off"
				>
			</div>

			<div class="uc-field">
				<label class="uc-label" for="uc-artwork-desc">
					<?php esc_html_e( 'Description (optional)', 'urban-canvas' ); ?>
				</label>
				<textarea
					class="uc-textarea"
					id="uc-artwork-desc"
					name="artwork_desc"
					rows="4"
					maxlength="1000"
					placeholder="<?php esc_attr_e( 'What inspired this piece? Where was it created?', 'urban-canvas' ); ?>"
				></textarea>
			</div>

			<div class="uc-field">
				<label class="uc-label" for="uc-artwork-file">
					<?php esc_html_e( 'Artwork File', 'urban-canvas' ); ?>
					<span class="uc-required" aria-hidden="true">*</span>
				</label>

				<div class="uc-dropzone" id="uc-dropzone" role="button" tabindex="0" aria-label="<?php esc_attr_e( 'Click or drag file here to upload', 'urban-canvas' ); ?>">
					<div class="uc-dropzone__icon" aria-hidden="true">
						<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
							<polyline points="16 16 12 12 8 16"></polyline>
							<line x1="12" y1="12" x2="12" y2="21"></line>
							<path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"></path>
						</svg>
					</div>
					<p class="uc-dropzone__text"><?php esc_html_e( 'Drag and drop your file here, or click to browse', 'urban-canvas' ); ?></p>
					<p class="uc-dropzone__hint"><?php esc_html_e( 'JPG, PNG or PDF · Max 10 MB', 'urban-canvas' ); ?></p>
					<div class="uc-dropzone__preview" id="uc-file-preview" hidden>
						<span class="uc-dropzone__filename" id="uc-filename"></span>
						<button type="button" class="uc-dropzone__remove" id="uc-remove-file" aria-label="<?php esc_attr_e( 'Remove file', 'urban-canvas' ); ?>">✕</button>
					</div>
				</div>

				<input
					type="file"
					id="uc-artwork-file"
					name="artwork_file"
					accept=".jpg,.jpeg,.png,.pdf"
					required
					style="position:absolute;width:1px;height:1px;opacity:0;pointer-events:none"
					aria-hidden="true"
				>
			</div>
		</fieldset>

		<div class="uc-privacy-notice">
			<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
			<?php esc_html_e( 'Your artwork is scanned for security and all GPS/location metadata is automatically removed before storage to protect your privacy.', 'urban-canvas' ); ?>
		</div>

		<div class="uc-submit-row">
			<button type="submit" class="uc-button uc-button--primary" id="uc-submit-btn">
				<span class="uc-button__text"><?php esc_html_e( 'Submit Artwork', 'urban-canvas' ); ?></span>
				<span class="uc-button__spinner" aria-hidden="true" hidden></span>
			</button>
		</div>

	</form>

</div>
