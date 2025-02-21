<?php
namespace Login_With_AJAX\Passkeys;

use Login_With_AJAX\TwoFA;

/**
 * Handles output of setup forms for users, such as on profile page, and also the UI-side of Passkey registration (Server object handles the AJAX side of things).
 */
class Account {
	
	public static function init() {
		// hook into profile page
		if( TwoFA::is_enabled() && !empty(\LoginWithAjax::$data['passkeys']['2FA']) ) {
			// add it above the TwoFA content, therefore disable the title of TwoFA so PK title takes over
			add_filter('lwa_2FA_account_show_profile_fields_title', '__return_empty_string');
		} else {
			// Show PK fields
			add_action( 'show_user_profile', array( static::class, 'show_profile_fields' ), 1 );
			add_action( 'edit_user_profile', array( static::class, 'show_profile_fields' ), 1 );
			
			// BP integration
			add_action('bp_core_general_settings_before_submit', array( static::class, 'show_profile_fields_current_user' ) );
			
			// WC integration
			add_action('woocommerce_edit_account_form', array( static::class, 'show_profile_fields_current_user' ) );
		}
		add_shortcode('lwa_passkeys_editor', array( static::class, 'shortcode' ), 1 );
	}
	
	public static function show_profile_fields( $user ) {
		?>
		<h3><?php esc_html_e("Passkeys", 'login-with-ajax-pro'); ?></h3>
		<p><?php esc_html_e("Passkeys offer a secure and user-friendly login method without passwords, utilizing unique digital keys or biometric data from your device, like fingerprints or facial recognition, to ensure unparalleled security and protect your account from phishing and hacking.", 'login-with-ajax-pro'); ?></p>
		<?php
		self::editor( $user );
	}
	
	public static function show_profile_fields_current_user() {
		static::show_profile_fields( wp_get_current_user() );
	}
	
	public static function shortcode( $atts ) {
		ob_start();
		if ( is_user_logged_in() ) {
			$user = wp_get_current_user();
			self::editor( $user );
		} else {
			echo '<p>' . esc_html__('You must be logged in to view this content.', 'login-with-ajax-pro') . '</p>';
		}
		return ob_get_clean();
	}
	
	public static function editor( $user, $force_user = false ) {
		$passkeys_data = get_user_meta( $user->ID, 'lwa_passkeys', true );
		if( !is_array($passkeys_data) ) $passkeys_data = array();
		$passkeys_template = array( (object) array(
			'label' => 'New Device',
			'created' => time(),
			'last_used' => 0,
			'rpId' => 'all',
		));
		$passkeys = $passkeys_template + $passkeys_data;
		$multidomain = Server::is_multidomain( $user->ID );
		?>
		<div class="lwa-wrapper lwa-bones">
			<div class="lwa pixelbones lwa-passkeys-editor">
				<header>
					<div><?php esc_html_e('Your Passkeys', 'login-with-ajax-pro'); ?></div>
					<div>
						<?php if ( $force_user || get_current_user_id() === $user->ID ) : ?>
							<button type="button" class="lwa-passkey-button-add button button-primary" data-text-loading="<?php esc_attr_e('Adding...', 'login-with-ajax-pro'); ?>" data-nonce-get="<?php echo wp_create_nonce('lwa_passkeys_getCreateArgs'); ?>" data-nonce-process="<?php echo wp_create_nonce('lwa_passkeys_processCreate'); ?>"><?php esc_html_e('Add Passkey', 'login-with-ajax-pro'); ?></button>
						<?php endif; ?>
					</div>
				</header>
				<ul class="lwa-passkeys" data-multidomain="<?php echo $multidomain ? 1 : 0; ?>">
					<li class="no-passkeys <?php if( count($passkeys) > 1 ) echo 'hidden'; ?>">
						<?php esc_html_e('No passkeys registered', 'login-with-ajax-pro'); ?>
					</li>
					<?php foreach( $passkeys as $passkey_id => $passkey ) : ?>
						<li class="lwa-passkey <?php if ( $passkey_id == 0 ) echo 'passkey-template hidden'; ?>" data-passkey-id="<?php echo esc_attr( $passkey_id ); ?>">
							<div class="passkey-view passkey-info">
								<svg viewBox="0 0 20.00 20.00" xmlns="http://www.w3.org/2000/svg" fill="#000000" stroke="#000000" stroke-width="0.0002"><g id="SVGRepo_bgCarrier" stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"> <path fill-rule="evenodd" d="M16.6945 12.1334C16.3969 12.3459 16.3035 12.792 16.562 13.0505C16.8653 13.3538 16.8653 13.8454 16.562 14.1487L16.4444 14.2663C16.0763 14.6345 16.0763 15.2314 16.4444 15.5996C16.8126 15.9678 16.8126 16.5647 16.4444 16.9329L15.6869 17.6905C15.4916 17.8858 15.175 17.8858 14.9798 17.6905L13.8484 16.5592C13.6609 16.3716 13.5556 16.1173 13.5556 15.8521V12.4113C12.5045 11.912 11.7778 10.8407 11.7778 9.59961C11.7778 7.88139 13.1707 6.48849 14.8889 6.48849C16.6071 6.48849 18 7.88139 18 9.59961C18 10.6446 17.4848 11.5693 16.6945 12.1334ZM14.8889 8.26627C15.3798 8.26627 15.7778 8.66424 15.7778 9.15516C15.7778 9.64608 15.3798 10.044 14.8889 10.044C14.398 10.044 14 9.64608 14 9.15516C14 8.66424 14.398 8.26627 14.8889 8.26627Z" fill="#5C5F62"></path> <path d="M10.7017 11.0931C10.0031 10.9296 9.1829 10.8342 8.22222 10.8342C3.16667 10.8342 2 13.4757 2 14.7848C2 16.0939 3.04467 17.1552 4.33333 17.1552H12.1111C12.1484 17.1552 12.1854 17.1543 12.2222 17.1525V13.1552C11.5324 12.637 10.9975 11.9221 10.7017 11.0931Z" fill="#5C5F62"></path> <path d="M8 9C9.65685 9 11 7.65685 11 6C11 4.34315 9.65685 3 8 3C6.34315 3 5 4.34315 5 6C5 7.65685 6.34315 9 8 9Z" fill="#5C5F62"></path> </g></svg>
								<div class="passkey-info">
									<div class="passkey-label">
										<?php esc_html_e( $passkey->label ); ?>
									</div>
									<div class="passkey-history">
										<?php echo sprintf(esc_html__('Created on %s'), '<span class="created-on">' . date_i18n( get_option('date_format'), $passkey->created ) . '</span>' ); ?> |
										<?php if( $passkey->last_used ) : ?>
											<?php echo sprintf(esc_html__('Last used %s ago'), '<span class="last-used">' . human_time_diff( $passkey->last_used, time() ) . '</span>' ); ?>
										<?php else : ?>
											<?php esc_html_e('Never used', 'login-with-ajax-pro'); ?>
										<?php endif; ?>
									</div>
									<div class="passkey-domain">
										<?php echo sprintf( esc_html__('Valid for %s', 'login-with-ajax-pro'), '<span class="passkey-rpId">'.esc_html($passkey->rpId).'</span>' ); ?>
									</div>
								</div>
								<div class="passkey-actions">
									<button type="button" class="lwa-passkey-button-edit button button-secondary" aria-label="<?php esc_html_e('Edit', 'login-with-ajax-pro'); ?>">
										<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" stroke="#545454"><g id="SVGRepo_bgCarrier" stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"> <path d="M12 20H20.5M18 10L21 7L17 3L14 6M18 10L8 20H4V16L14 6M18 10L14 6" stroke="#5c5c5c" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"></path> </g></svg>
									</button>
									<button type="button" class="lwa-passkey-button-delete button button-secondary" aria-label="<?php esc_html_e('Remove', 'login-with-ajax-pro'); ?>">
										<svg class="loader hidden" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 100 100" preserveAspectRatio="xMidYMid">
											<rect x="17.5" y="40" width="15" height="40" fill="#85a2b6">
												<animate attributeName="y" repeatCount="indefinite" dur="1.4492753623188404s" calcMode="spline" keyTimes="0;0.5;1" values="14;30;30" keySplines="0 0.5 0.5 1;0 0.5 0.5 1" begin="-0.2898550724637681s"></animate>
												<animate attributeName="height" repeatCount="indefinite" dur="1.4492753623188404s" calcMode="spline" keyTimes="0;0.5;1" values="72;40;40" keySplines="0 0.5 0.5 1;0 0.5 0.5 1" begin="-0.2898550724637681s"></animate>
											</rect>
											<rect x="42.5" y="40" width="15" height="40" fill="#bbcedd">
												<animate attributeName="y" repeatCount="indefinite" dur="1.4492753623188404s" calcMode="spline" keyTimes="0;0.5;1" values="18;30;30" keySplines="0 0.5 0.5 1;0 0.5 0.5 1" begin="-0.14492753623188406s"></animate>
												<animate attributeName="height" repeatCount="indefinite" dur="1.4492753623188404s" calcMode="spline" keyTimes="0;0.5;1" values="64;40;40" keySplines="0 0.5 0.5 1;0 0.5 0.5 1" begin="-0.14492753623188406s"></animate>
											</rect>
											<rect x="67.5" y="40" width="15" height="40" fill="#dce4eb">
												<animate attributeName="y" repeatCount="indefinite" dur="1.4492753623188404s" calcMode="spline" keyTimes="0;0.5;1" values="18;30;30" keySplines="0 0.5 0.5 1;0 0.5 0.5 1"></animate>
												<animate attributeName="height" repeatCount="indefinite" dur="1.4492753623188404s" calcMode="spline" keyTimes="0;0.5;1" values="64;40;40" keySplines="0 0.5 0.5 1;0 0.5 0.5 1"></animate>
											</rect>
										</svg>
										<svg viewBox="0 0 1024 1024" class="passkey-delete-icon" version="1.1" xmlns="http://www.w3.org/2000/svg" fill="#000000"><g id="SVGRepo_bgCarrier" stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round" stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"><path d="M960 160h-291.2a160 160 0 0 0-313.6 0H64a32 32 0 0 0 0 64h896a32 32 0 0 0 0-64zM512 96a96 96 0 0 1 90.24 64h-180.48A96 96 0 0 1 512 96zM844.16 290.56a32 32 0 0 0-34.88 6.72A32 32 0 0 0 800 320a32 32 0 1 0 64 0 33.6 33.6 0 0 0-9.28-22.72 32 32 0 0 0-10.56-6.72zM832 416a32 32 0 0 0-32 32v96a32 32 0 0 0 64 0v-96a32 32 0 0 0-32-32zM832 640a32 32 0 0 0-32 32v224a32 32 0 0 1-32 32H256a32 32 0 0 1-32-32V320a32 32 0 0 0-64 0v576a96 96 0 0 0 96 96h512a96 96 0 0 0 96-96v-224a32 32 0 0 0-32-32z" fill="#8d4834"></path><path d="M384 768V352a32 32 0 0 0-64 0v416a32 32 0 0 0 64 0zM544 768V352a32 32 0 0 0-64 0v416a32 32 0 0 0 64 0zM704 768V352a32 32 0 0 0-64 0v416a32 32 0 0 0 64 0z" fill="#8d4834"></path></g></svg>
									</button>
								</div>
							</div>
							<div class="passkey-view passkey-editor hidden">
								<div>
									<input type="text" class="passkey-label" value="<?php esc_html_e( $passkey->label ); ?>" placeholder="<?php esc_attr_e('Passkey Label'); ?>">
									<p><em><?php esc_html_e('Give this passkey a name for your own reference.', 'login-with-ajax-pro'); ?></em></p>
								</div>
								<div class="passkey-actions">
									<button type="button" class="lwa-passkey-button-edit-save" data-text-loading="<?php esc_attr_e('Saving...', 'login-with-ajax-pro'); ?>"><?php esc_html_e('Save'); ?></button>
									<button type="button" class="lwa-passkey-button-edit-cancel"><?php esc_html_e('Cancel'); ?></button>
								</div>
							</div>
						</li>
					<?php endforeach; ?>
				</ul>
			</div>
		</div>
		<?php
	}
}

Account::init();