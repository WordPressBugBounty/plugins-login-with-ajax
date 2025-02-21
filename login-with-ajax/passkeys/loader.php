<?php
if ( is_admin() ) {
	include('passkeys-admin.php');
}
if( !empty(LoginWithAjax::$data['passkeys']['enabled']) ) {
	include('passkeys.php');
	include('passkeys-frontend.php');
	include('passkeys-server.php');
	include('passkeys-account.php');
	if( !empty(LoginWithAjax::$data['passkeys']['2FA']) ) {
		add_action('lwa_2FA_loaded_pro', 'lwa_passkeys_2FA_load');
	}
}
function lwa_passkeys_2FA_load() {
	include('2FA-passkeys.php');
}