/**
 * Urban Canvas — Submission Form JS
 *
 * Handles:
 *   - Drag-and-drop file selection with client-side pre-validation.
 *   - AJAX form submission with progress feedback.
 *   - Accessible error/success notices.
 */
( function ( $, cfg ) {
	'use strict';

	var MAX_BYTES    = cfg.maxSizeMB * 1024 * 1024;
	var ALLOWED_EXTS = [ 'jpg', 'jpeg', 'png', 'pdf' ];

	var $form       = $( '#uc-submission-form' );
	var $notice     = $( '#uc-notice' );
	var $dropzone   = $( '#uc-dropzone' );
	var $fileInput  = $( '#uc-artwork-file' );
	var $preview    = $( '#uc-file-preview' );
	var $filename   = $( '#uc-filename' );
	var $removeBtn  = $( '#uc-remove-file' );
	var $submitBtn  = $( '#uc-submit-btn' );

	// ── Dropzone ──────────────────────────────────────────────────────────────

	$dropzone.on( 'click keypress', function ( e ) {
		if ( 'click' === e.type || 13 === e.which ) {
			$fileInput.trigger( 'click' );
		}
	} );

	$dropzone.on( 'dragover dragenter', function ( e ) {
		e.preventDefault();
		$dropzone.addClass( 'is-over' );
	} );

	$dropzone.on( 'dragleave drop', function ( e ) {
		e.preventDefault();
		$dropzone.removeClass( 'is-over' );
		if ( 'drop' === e.type ) {
			var files = e.originalEvent.dataTransfer.files;
			if ( files.length ) {
				setFile( files[ 0 ] );
			}
		}
	} );

	$fileInput.on( 'change', function () {
		if ( this.files && this.files[ 0 ] ) {
			setFile( this.files[ 0 ] );
		}
	} );

	$removeBtn.on( 'click', function ( e ) {
		e.stopPropagation();
		clearFile();
	} );

	function setFile( file ) {
		clearNotice();

		// Client-side type check (server re-validates authoritatively).
		var ext = file.name.split( '.' ).pop().toLowerCase();
		if ( ALLOWED_EXTS.indexOf( ext ) === -1 ) {
			showNotice( cfg.i18n.wrongType, 'error' );
			clearFile();
			return;
		}

		// Client-side size check.
		if ( file.size > MAX_BYTES ) {
			showNotice(
				cfg.i18n.fileTooBig.replace( '%s', cfg.maxSizeMB ),
				'error'
			);
			clearFile();
			return;
		}

		// Transfer to the hidden input via DataTransfer.
		try {
			var dt = new DataTransfer();
			dt.items.add( file );
			$fileInput[ 0 ].files = dt.files;
		} catch ( err ) {
			// Fallback: rely on the file input being set by drag-drop event directly.
		}

		$filename.text( file.name + ' (' + formatBytes( file.size ) + ')' );
		$preview.removeAttr( 'hidden' );
		$dropzone.addClass( 'has-file' );
		$dropzone.find( '.uc-dropzone__icon, .uc-dropzone__text, .uc-dropzone__hint' ).hide();
	}

	function clearFile() {
		$fileInput.val( '' );
		$preview.attr( 'hidden', true );
		$dropzone.removeClass( 'has-file' );
		$dropzone.find( '.uc-dropzone__icon, .uc-dropzone__text, .uc-dropzone__hint' ).show();
	}

	// ── Form Submit ───────────────────────────────────────────────────────────

	$form.on( 'submit', function ( e ) {
		e.preventDefault();
		clearNotice();

		if ( ! $fileInput[ 0 ].files || ! $fileInput[ 0 ].files[ 0 ] ) {
			showNotice( cfg.i18n.wrongType, 'error' );
			return;
		}

		var fd = new FormData( $form[ 0 ] );
		fd.append( 'action', cfg.action );
		fd.append( 'nonce',  cfg.nonce );

		setLoading( true );
		showNotice( cfg.i18n.uploading, 'info' );

		$.ajax( {
			url:         cfg.ajaxurl,
			method:      'POST',
			data:        fd,
			processData: false,
			contentType: false,
			xhr: function () {
				var xhr = new window.XMLHttpRequest();
				xhr.upload.addEventListener( 'progress', function ( ev ) {
					if ( ev.lengthComputable ) {
						var pct = Math.round( ( ev.loaded / ev.total ) * 100 );
						updateProgress( pct );
					}
				} );
				return xhr;
			},
			success: function ( response ) {
				setLoading( false );
				if ( response.success ) {
					showNotice( response.data.message, 'success' );
					$form[ 0 ].reset();
					clearFile();
					removeProgress();
				} else {
					showNotice( response.data.message || 'Submission failed.', 'error' );
				}
			},
			error: function ( xhr ) {
				setLoading( false );
				var msg = 'An error occurred. Please try again.';
				if ( xhr.responseJSON && xhr.responseJSON.data ) {
					msg = xhr.responseJSON.data.message || msg;
				}
				showNotice( msg, 'error' );
			}
		} );
	} );

	// ── Helpers ───────────────────────────────────────────────────────────────

	function setLoading( state ) {
		$submitBtn.prop( 'disabled', state );
		$submitBtn.find( '.uc-button__spinner' ).attr( 'hidden', ! state || null );
	}

	function showNotice( message, type ) {
		$notice
			.removeClass( 'is-success is-error is-info' )
			.addClass( 'is-' + type )
			.text( message )
			.removeAttr( 'hidden' )
			.get( 0 ).scrollIntoView( { behavior: 'smooth', block: 'nearest' } );
	}

	function clearNotice() {
		$notice.attr( 'hidden', true ).text( '' );
	}

	function updateProgress( pct ) {
		if ( ! $( '#uc-progress' ).length ) {
			$form.prepend( '<div class="uc-progress" id="uc-progress"><div class="uc-progress__bar" id="uc-progress-bar"></div></div>' );
		}
		$( '#uc-progress-bar' ).css( 'width', pct + '%' );
	}

	function removeProgress() {
		$( '#uc-progress' ).remove();
	}

	function formatBytes( bytes ) {
		if ( bytes < 1024 ) return bytes + ' B';
		if ( bytes < 1048576 ) return ( bytes / 1024 ).toFixed( 1 ) + ' KB';
		return ( bytes / 1048576 ).toFixed( 1 ) + ' MB';
	}

} )( jQuery, window.ucSubmit || {} );
