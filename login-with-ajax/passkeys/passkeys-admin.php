<?php
namespace Login_With_AJAX\Passkeys;

class Admin {
	public static function init(){
		$class = get_called_class();
		add_action('lwa_settings_security', '\\'.$class.'::admin_settings', 10);
	}
	
	public static function admin_settings(){
		$lwa = get_option('lwa_data', array());
		$passkeys = !empty($lwa['passkeys']) ? $lwa['passkeys']: array('enabled' => false);
		$docs_link = '<a href="https://docs.loginwithajax.com/security/passkeys/" target="_blank">'. esc_html__('documentation','login-with-ajax-pro') .'</a>';
		?>
		<h3><?php esc_html_e("Passkeys (FIDO2 & Webauth)", 'login-with-ajax-pro'); ?></h3>
		<p><em><?php esc_html_e("Passkeys offer a secure and user-friendly login method without passwords, utilizing unique digital keys or biometric data from your device, like fingerprints or facial recognition, to ensure unparalleled security and protect your account from phishing and hacking.", 'login-with-ajax-pro'); ?></em></p>
		<p><em><?php echo sprintf( esc_html__("For more information and recommendations please see our %s page.", 'login-with-ajax-pro'), $docs_link); ?></em></p>
		<table class="form-table">
			<tr valign="top">
				<th scope="row">
					<label><?php esc_html_e("Enable Passkeys", 'login-with-ajax-pro'); ?></label>
				</th>
				<td>
					<input type="checkbox" name="lwa_passkeys[enabled]" id="lwa_passkeys_enable" value='1' <?php echo ( !empty($passkeys['enabled']) ) ? 'checked':''; ?> >
				</td>
			</tr>
			<tbody class="lwa-settings-passkeys">
				<tr valign="top" class="lwa-settings-2FA-thirdparty">
					<th scope="row">
						<label><?php esc_html_e("Enable as a 2FA method?", 'login-with-ajax-pro'); ?></label>
					</th>
					<td>
						<input type="checkbox" name="lwa_passkeys[2FA]" id="lwa_passkeys_2FA" value='1' <?php echo ( !empty($passkeys['2FA']) ) ? 'checked':''; ?> >
						<p><em><?php esc_html_e("Show Passkeys as a 2FA method, if a user logs into their account using regular passwords they can use their passkey as a way to verify their identity via 2FA.", 'login-with-ajax-pro'); ?></em></p>
					</td>
				</tr>
			</tbody>
			<?php do_action('lwa_settings_passkeys_footer'); ?>
		</table>
		<script type="text/javascript">
			jQuery(document).ready( function($){
				$('#lwa_passkeys_enable').on('click', function( event ){
					if( $(this).prop('checked') ){
						$('tr.lwa-settings-2FA-thirdparty').show();
						$('option.lwa-settings-2FA-thirdparty, input[type="checkbox"].lwa-settings-2FA-thirdparty').prop('disabled', false);
						$('.lwa-settings-passkeys').show();
					}else{
						let confirm_message = '<?php echo esc_js('Disabling passkeys may prevent users who have set up passkeys from logging into their accounts this way, and will fall back to other enabled methods or via regular username/passwords.', 'login-with-ajax-pro'); ?>';
						if( confirm( confirm_message ) ) {
							$('.lwa-settings-passkeys').hide();
						} else {
							event.preventDefault();
							return false;
						}
					}
				});
				if( !$('#lwa_passkeys_enable').prop('checked') ){
					$('.lwa-settings-passkeys').hide();
				}
			});
		</script>
		<?php
	}
}
Admin::init();