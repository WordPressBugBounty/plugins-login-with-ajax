<?php
namespace Login_With_AJAX\TwoFA\Method;

use Login_With_AJAX\Passkeys\Frontend;
use Login_With_AJAX\Passkeys\Account;
use Login_With_AJAX\TwoFA;
use WP_User;

class Passkeys extends Method {
	
	public static $method = 'passkeys';
	public static $authentication_resend = false;
	
	public static $needs_setup = true;
	public static $svg_icon = '<svg viewBox="0 0 20.00 20.00" xmlns="http://www.w3.org/2000/svg" fill="#000000" stroke="#000000" stroke-width="0.0002"><g id="SVGRepo_bgCarrier" stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"> <path fill-rule="evenodd" d="M16.6945 12.1334C16.3969 12.3459 16.3035 12.792 16.562 13.0505C16.8653 13.3538 16.8653 13.8454 16.562 14.1487L16.4444 14.2663C16.0763 14.6345 16.0763 15.2314 16.4444 15.5996C16.8126 15.9678 16.8126 16.5647 16.4444 16.9329L15.6869 17.6905C15.4916 17.8858 15.175 17.8858 14.9798 17.6905L13.8484 16.5592C13.6609 16.3716 13.5556 16.1173 13.5556 15.8521V12.4113C12.5045 11.912 11.7778 10.8407 11.7778 9.59961C11.7778 7.88139 13.1707 6.48849 14.8889 6.48849C16.6071 6.48849 18 7.88139 18 9.59961C18 10.6446 17.4848 11.5693 16.6945 12.1334ZM14.8889 8.26627C15.3798 8.26627 15.7778 8.66424 15.7778 9.15516C15.7778 9.64608 15.3798 10.044 14.8889 10.044C14.398 10.044 14 9.64608 14 9.15516C14 8.66424 14.398 8.26627 14.8889 8.26627Z" fill="#5C5F62"></path> <path d="M10.7017 11.0931C10.0031 10.9296 9.1829 10.8342 8.22222 10.8342C3.16667 10.8342 2 13.4757 2 14.7848C2 16.0939 3.04467 17.1552 4.33333 17.1552H12.1111C12.1484 17.1552 12.1854 17.1543 12.2222 17.1525V13.1552C11.5324 12.637 10.9975 11.9221 10.7017 11.0931Z" fill="#5C5F62"></path> <path d="M8 9C9.65685 9 11 7.65685 11 6C11 4.34315 9.65685 3 8 3C6.34315 3 5 4.34315 5 6C5 7.65685 6.34315 9 8 9Z" fill="#5C5F62"></path> </g></svg>';
	
	public static function init () {
		parent::init();
		// add passkeys to top of list
		$passkeys = TwoFA::$methods[static::$method];
		unset(TwoFA::$methods[static::$method]);
		TwoFA::$methods = array_merge(array(static::$method => $passkeys), TwoFA::$methods);
		// add new ajax urls to login_response
		add_filter('lwa_2FA_login_response', array(static::class, 'lwa_2FA_login_response'), 10, 2);
	}
	
	public static function lwa_2FA_login_response( $response, $user ) {
		$response['passkeys'] = array(
			'url' => \Login_With_AJAX\Passkeys\Passkeys::get_urls( $user->ID ),
		);
		return $response;
	}
	
	public static function get_name () {
		return esc_html__('Passkeys', 'login-with-ajax');
	}
	
	public static function is_enabled( $user ) {
		return static::is_setup( $user );
	}
	
	/**
	 * @return string
	 */
	public static function get_text_select( $user ){
		return esc_html__('Use a Passkey.', 'login-with-ajax-pro');
	}
	
	public static function get_text_request ( $user ) {
		return esc_html__('Use a Passkey you have previously registered using one of your devices.', 'login-with-ajax');
	}
	
	/**
	 * Overriden to add filter to child function.
	 * @param $user
	 *
	 * @return bool|mixed|null
	 */
	public static function is_ready( $user ) {
		$ready = parent::is_ready( $user );
		return apply_filters('lwa_2FA_method_passkey_is_ready', $ready, $user);
	}
	
	/**
	 * Check that user has saved secret in user meta.
	 * @param $user
	 * @return bool|mixed|null
	 */
	public static function is_setup( $user ) {
		$setup = false;
		if( $user ) {
			$passkeys = get_user_meta($user->ID, 'lwa_passkeys', true);
			$setup = !empty($passkeys);
		}
		return apply_filters('lwa_2FA_method_passkey_is_setup', $setup, $user);
	}
	
	/**
	 * Assumes that $_REQUEST['2FA_code'] presence, general timeout etc. is checked before firing this filter.
	 * @param array $response
	 * @param WP_User $user
	 * @return array
	 */
	public static function verify( $response, $user ){
		if( !empty($_REQUEST['2FA_code']) && preg_match('/^[0-9A-Za-z]{10}$/', $_REQUEST['2FA_code']) ) {
			$codes = self::get_codes( $user );
			if( isset($codes[$_REQUEST['2FA_code']]) ) {
				// check if code was used already
				if( $codes[$_REQUEST['2FA_code']] > 0 ) {
					$response['result'] = false;
					$response['error'] = esc_html__('Backup code already used, please try another.', 'login-with-ajax-pro');
				} else {
					$response['result'] = true;
					$methods = \LoginWithAjax::get_user_meta( $user->ID, '2FA[methods]' );
					$methods[ static::$method ]['codes'][$_REQUEST['2FA_code']] = time(); // mark code as used
					\LoginWithAjax::update_user_meta( $user->ID, '2FA[methods]', $methods );
				}
			} else {
				$response['result'] = false;
				$response['error'] = esc_html__('Invalid backup code, please try again.', 'login-with-ajax-pro');
			}
		} else {
			$response['result'] = false;
			$response['error'] = esc_html__('Incorrect verification code, please try again.', 'login-with-ajax-pro');
		}
		return $response;
	}
	
	public static function get_form_fields( $user = null ) {
		ob_start();
		?>
		<div class="lwa-2FA-code-input-wrap">
			<div class="lwa-2FA-code-input">
				<?php Frontend::login_form( false ); ?>
			</div>
		</div>
		<?php
		return ob_get_clean();
	}
	
	/* Setup Function */
	
	public static function get_setup_description () {
		return esc_html__("Passkeys offer a secure and user-friendly login method without passwords, utilizing unique digital keys or biometric data from your device, like fingerprints or facial recognition, to ensure unparalleled security and protect your account from phishing and hacking.", 'login-with-ajax-pro');
	}
	
	public static function get_setup_status_ready_text ( $user ) {
		return esc_html__('Passkeys are set up and ready to be used.', 'login-with-ajax');
	}
	
	public static function setup( $user, $single = false ) {
		// enable passkeys method for this step
		add_filter('lwa_2FA_method_passkey_is_setup', '__return_true');
		parent::setup( $user, $single );
		remove_filter('lwa_2FA_method_passkey_is_setup', '__return_true');
		// check if we have other methods to setup, if so we add a title here specific to group up the rest
		$methods = TwoFA::get_available_methods( $user );
		if( count($methods) > 1 ) {
			?>
			<h4><?php _e('Two Factor Authentication (2FA)','login-with-ajax'); ?></h4>
			<p><?php esc_html_e('2FA provides an extra layer of security in case your username and password is compromised, preventing any attacker from logging into your account without further authentication. We recommend enabling at least one 2FA method to secure your account.', 'login-with-ajax'); ?></p>
			<?php
		}
	}
	
	public static function setup_header( $user, $show_switch = true ) {
		parent::setup_header( $user, false );
	}
	
	public static function setup_footer( $user ) {
		Account::editor( $user, true );
	}
}
Passkeys::init();