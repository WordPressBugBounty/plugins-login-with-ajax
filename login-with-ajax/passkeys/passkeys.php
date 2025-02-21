<?php
namespace Login_With_AJAX\Passkeys;
use Login_With_AJAX\TwoFA;

class Passkeys {
	public static function init(){
		// add script registration and enqueuing
		add_action('lwa_enqueue', array(static::class, 'enqueue_scripts_and_styles'));
		add_action( 'login_enqueue_scripts', array( static::class, 'enqueue_scripts_and_styles' ) );
		add_filter('lwa_js_vars', array(static::class, 'localize_script'));
		if( is_admin() ) {
			global $pagenow;
			if( $pagenow === 'profile.php' || $pagenow === 'user-edit.php' ) {
				add_action( 'admin_enqueue_scripts', array( static::class, 'enqueue_scripts_and_styles' ) );
			}
		}
		// force-enable 2FA method if enabled in passkeys settings
		if( !empty(\LoginWithAjax::$data['passkeys']['2FA']) ) {
			\LoginWithAjax::$data['2FA']['methods']['passkeys'] = true;
		}
	}
	
	public static function enqueue_scripts_and_styles() {
		$version = LWA_PRO_VERSION;
		TwoFA::register_scripts_and_styles();
		$footer = did_action('admin_enequeue_scripts') || did_action('lwa_enqueue') ? array() : array('in_footer' => true);
		if ( ( defined('WP_DEBUG') && WP_DEBUG ) || ( defined('LWA_DEBUG') && constant('LWA_DEBUG') ) ) {
			wp_enqueue_script( "login-with-ajax-passkeys", plugin_dir_url( __FILE__ ) . 'passkeys.js', array(), $version, $footer );
			wp_enqueue_style( "login-with-ajax-passkeys", plugin_dir_url( __FILE__ ) . 'passkeys.css', array('login-with-ajax-2FA'), $version );
		} else {
			wp_enqueue_script( "login-with-ajax-passkeys", plugin_dir_url( __FILE__ ) . 'passkeys.min.js', array(), $version, $footer );
			wp_enqueue_style( "login-with-ajax-passkeys", plugin_dir_url( __FILE__ ) . 'passkeys.min.css', array('login-with-ajax-2FA'), $version );
		}
		\LoginWithAjax::localize_js('login-with-ajax-passkeys');
	}
	
	public static function localize_script( $vars ) {
		$user_id = !empty($_REQUEST['user_id']) && current_user_can('edit_users') ? $_REQUEST['user_id'] : get_current_user_id();
		$vars['passkeys'] = array(
			'txt' => array(
				'cancelled' => esc_html__('Passkey verification cancelled or not allowed, please try again.', 'login-with-ajax-pro'),
			),
			'url' => static::get_urls( $user_id ),
		);
		return $vars;
	}
	
	public static function get_urls( $user_id ) {
		$user = get_user_by('ID', $user_id);
		$user_login = $user->user_login ?? null;
		if( !empty( $_REQUEST['reauth']) ) {
			// WP issue which thinks it's still logged in when petitioning a reauth, so here so force a non-logged in user for the nonce creation, otherwise the nonce won't validate next ajax call
			$current_user_id = get_current_user_id();
			if( !empty($_COOKIE[ LOGGED_IN_COOKIE ]) ) {
				$cookie = $_COOKIE[ LOGGED_IN_COOKIE ];
				$_COOKIE[ LOGGED_IN_COOKIE ] = '';
			}
			wp_set_current_user( 0 );
			add_filter('nonce_user_logged_out', '__return_zero', 9999999);
			add_filter('determine_current_user', '__return_zero', 9999999);
			$getGetArgs_nonce = wp_create_nonce('lwa_passkeys_getGetArgs');
			$processGet_nonce = wp_create_nonce('lwa_passkeys_processGet');
			// reset user as before, in case WP had other things in mind :/
			wp_set_current_user( $current_user_id );
			remove_filter('nonce_user_logged_out', '__return_zero');
			remove_filter('determine_current_user', '__return_zero');
			if( !empty($cookie) ) $_COOKIE[ LOGGED_IN_COOKIE ] = $cookie;
		} else {
			$getGetArgs_nonce = wp_create_nonce('lwa_passkeys_getGetArgs');
			$processGet_nonce = wp_create_nonce('lwa_passkeys_processGet');
		}
		return array(
			'create' => add_query_arg( array('action' => 'lwa_passkeys', 'fn' => 'getCreateArgs', 'log' => $user_login, 'nonce' => wp_create_nonce('lwa_passkeys_getCreateArgs-'.$user_id) ), admin_url('admin-ajax.php') ),
			'register' => add_query_arg( array('action' => 'lwa_passkeys', 'fn' => 'processCreate', 'log' => $user_login, 'nonce' => wp_create_nonce('lwa_passkeys_processCreate-'.$user_id) ), admin_url('admin-ajax.php') ),
			'get' => add_query_arg( array('action' => 'lwa_passkeys', 'fn' => 'getGetArgs', 'nonce' => $getGetArgs_nonce ), admin_url('admin-ajax.php') ),
			'verify' => add_query_arg( array('action' => 'lwa_passkeys', 'fn' => 'processGet', 'nonce' => $processGet_nonce ), admin_url('admin-ajax.php') ),
			'delete' => add_query_arg( array('action' => 'lwa_passkeys', 'fn' => 'delete', 'log' => $user_login, 'nonce' => wp_create_nonce('lwa_passkeys_delete-'.$user_id) ), admin_url('admin-ajax.php') ),
			'edit' => add_query_arg( array('action' => 'lwa_passkeys', 'fn' => 'edit', 'log' => $user_login, 'nonce' => wp_create_nonce('lwa_passkeys_edit-'.$user_id) ), admin_url('admin-ajax.php') ),
		);
	}
}
Passkeys::init();