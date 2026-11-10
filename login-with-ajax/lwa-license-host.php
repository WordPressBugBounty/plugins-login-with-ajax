<?php
namespace Login_With_AJAX;

/**
 * Keeps Pro license and update traffic on the current host, Pro versions before 2.2 hard-code the previous one and cannot be reached any other way.
 */
class License_Host {

	const HOST = 'ajaxauth.com';
	const PREVIOUS_HOST = 'loginwithajax.com';

	public static function init() {
		add_action( 'plugins_loaded', array( static::class, 'repoint_pro' ), 0 );
		add_filter( 'pre_http_request', array( static::class, 'refuse_previous_host' ), 1, 3 );
	}

	public static function repoint_pro() {
		if ( ! class_exists( '\Login_With_AJAX\LWA_License', false ) ) {
			return;
		}
		foreach ( array( 'updates_url', 'activation_url', 'deactivation_url', 'purchase_url' ) as $url ) {
			LWA_License::$$url = str_replace( static::PREVIOUS_HOST, static::HOST, LWA_License::$$url );
		}
	}

	public static function refuse_previous_host( $preempt, $args, $url ) {
		if ( stripos( $url, static::PREVIOUS_HOST ) === false ) {
			return $preempt;
		}
		$host = rtrim( strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) ), '.' );
		if ( $host === static::PREVIOUS_HOST || substr( $host, - strlen( '.' . static::PREVIOUS_HOST ) ) === '.' . static::PREVIOUS_HOST ) {
			return new \WP_Error( 'lwa_previous_host', __( 'This host is no longer used by AJAX Auth.', 'login-with-ajax' ) );
		}
		return $preempt;
	}
}
License_Host::init();
