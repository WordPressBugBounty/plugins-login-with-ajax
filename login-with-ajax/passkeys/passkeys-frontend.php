<?php
namespace Login_With_AJAX\Passkeys;

class Frontend {
	
	public static function init() {
		// add login button to login form
		add_action('lwa_login_form', array( static::class, 'lwa_login_form' ) );
		add_action('login_form', array( static::class, 'login_form'), 10, 0 );
		add_action('woocommerce_login_form_end', array( static::class, 'login_form'), 10, 0 );
	}
	
	public static function lwa_login_form() {
		if( did_action('login_form') ) return;
		static::login_form();
	}
	
	public static function login_form( $show_or = true ) {
		// output passkeys button, hide by default
		?>
		<div class="lwa lwa-passkey-login hidden">
			<?php if ( $show_or ) : ?>
			<div class="lwa-hr"><?php esc_html_e('or', 'login-with-ajax'); ?></div>
			<?php endif; ?>
			<div class="not-supported hidden">
				<?php if ( ! is_ssl() && $_SERVER['HTTP_HOST'] !== 'localhost' ) : ?>
					<?php esc_html_e('Passkeys require a secure connection to work.', 'login-with-ajax-pro'); ?>
				<?php else : ?>
					<?php esc_html_e('Passkeys are not supported by your browser.', 'login-with-ajax-pro'); ?>
				<?php endif; ?>
			</div>
			<div class="not-fully-supported hidden">
				<?php esc_html_e('Passkeys support is limited on your browser.', 'login-with-ajax-pro'); ?>
			</div>
			<button type="button" class="lwa-passkey-button-login button button-primary" data-text-loading="<?php esc_html_e('Logging In ...', 'login-with-ajax-pro'); ?>"><?php esc_html_e('Login with Passkeys', 'login-with-ajax-pro'); ?></button>
		</div>
		<?php
	}
}
Frontend::init();