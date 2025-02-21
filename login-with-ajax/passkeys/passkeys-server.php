<?php
namespace Login_With_AJAX\Passkeys;

use lbuchs\WebAuthn\WebAuthn;

class Server {
	
	public static $current_user_id = 0;
	
	public static function init() {
		// add ajax action for receiving passkeys
		add_action('wp_ajax_lwa_passkeys', array( static::class, 'ajax_passkeys' ) );
		add_action('wp_ajax_nopriv_lwa_passkeys', array( static::class, 'ajax_passkeys' ) );
		add_action('wp_ajax_nopriv_lwa_passkey_login', array( static::class, 'ajax_passkeys' ) );
	}
	
	public static function ajax_passkeys() {
		// check nonce, if so then process the request
		$nonce_check = false;
		if ( !empty($_REQUEST['fn'])  ) {
			// check the nonce against users
			if( in_array( $_REQUEST['fn'], array('getCreateArgs', 'processCreate', 'edit', 'delete') ) ) {
				$nonce_check = \LoginWithAjax::check_user_and_nonce('lwa_passkeys_' . $_REQUEST['fn'] . '-', null, false);
			} else {
				$nonce_check = check_ajax_referer('lwa_passkeys_' . $_REQUEST['fn'], 'nonce', false);
			}
		}
		if ( !$nonce_check ) {
			wp_send_json( array( 'success' => false, 'result' => false, 'msg' => 'Invalid nonce' ) );
		}
		
		require_once 'webauthn/WebAuthn.php';
		try {
			session_start();
			
			// read get argument and post body
			$fn = filter_input(INPUT_GET, 'fn');
			$requireResidentKey = true; // client-side discoverable = true, otherwise we need to get userhandle
			$userVerification = 'preferred'; // ['required', 'preferred', 'discouraged']
			
			/*
			$userId = filter_input(INPUT_GET, 'userId', FILTER_SANITIZE_SPECIAL_CHARS);
			$userName = filter_input(INPUT_GET, 'userName', FILTER_SANITIZE_SPECIAL_CHARS);
			$userDisplayName = filter_input(INPUT_GET, 'userDisplayName', FILTER_SANITIZE_SPECIAL_CHARS);
			
			$userId = preg_replace('/[^0-9a-f]/i', '', $userId);
			$userName = preg_replace('/[^0-9a-z]/i', '', $userName);
			$userDisplayName = preg_replace('/[^0-9a-z öüäéèàÖÜÄÉÈÀÂÊÎÔÛâêîôû]/i', '', $userDisplayName);
			*/
			
			$post = trim(file_get_contents('php://input'));
			if ($post) {
				$post = json_decode($post, null, 512, JSON_THROW_ON_ERROR);
			}
				
				// Formats -  get none for now
				$formats = ['none'];
				/*
				$formats[] = 'android-key';
				$formats[] = 'android-safetynet';
				$formats[] = 'apple';
				$formats[] = 'fido-u2f';
				$formats[] = 'none';
				$formats[] = 'packed';
				$formats[] = 'tpm';
				*/
				
				// get domain of site
				$rpId = preg_replace('/^https?:\/\//', '', get_site_url());
				$rpId = preg_replace('/\/.*$/', '', $rpId); // just the domain we need
				
				// types selected on front end - all for nwo
				$typeUsb = true;
				$typeNfc = true;
				$typeBle = true;
				$typeInt = false;
				$typeHyb = true;
				
				// cross-platform: true, if type internal is not allowed
				//                 false, if only internal is allowed
				//                 null, if internal and cross-platform is allowed
				$crossPlatformAttachment = null;
				/**
				if (($typeUsb || $typeNfc || $typeBle || $typeHyb) && !$typeInt) {
					$crossPlatformAttachment = true;
					
				} else if (!$typeUsb && !$typeNfc && !$typeBle && !$typeHyb && $typeInt) {
					$crossPlatformAttachment = false;
				}
				 */
				
				// new Instance of the server library.
				// make sure that $rpId is the domain name.
				$WebAuthn = new WebAuthn('WebAuthn Library', $rpId, $formats);
				
				// add root certificates to validate new registrations
				/*
				$WebAuthn->addRootCertificates('rootCertificates/solo.pem');
				$WebAuthn->addRootCertificates('rootCertificates/apple.pem');
				$WebAuthn->addRootCertificates('rootCertificates/yubico.pem');
				$WebAuthn->addRootCertificates('rootCertificates/hypersecu.pem');
				$WebAuthn->addRootCertificates('rootCertificates/globalSign.pem');
				$WebAuthn->addRootCertificates('rootCertificates/googleHardware.pem');
				$WebAuthn->addRootCertificates('rootCertificates/microsoftTpmCollection.pem');
				$WebAuthn->addRootCertificates('rootCertificates/mds');
				*/
			
			if ($fn === 'getCreateArgs') {
				// nonce passed, so we can assume user has permission to create a passkey (for example, via 2FA in grace mode)
				$user = $nonce_check; /* @var \WP_User $user */
				// create user id and save to db
				$userId = get_user_meta( $user->ID, 'lwa_passkey_id', true );
				if( empty( $userId ) ) {
					// generate new hexadecimal string that is unique in wp_usermeta for key lwa_passkey_id
					global $wpdb;
					do {
						$userId = wp_generate_uuid4();
						$userId = preg_replace('/[^0-9a-z]/i', '', $userId);
						$results = $wpdb->get_results('SELECT meta_value FROM '. $wpdb->usermeta . ' WHERE meta_key="lwa_passkey_id" AND meta_value="'. $userId .'"');
					} while ( !empty($results) );
					add_user_meta( $user->ID, 'lwa_passkey_id', $userId, true );
				}
				
				$userName = $user->user_login;
				$userDisplayName = $user->display_name;
				
				// create args and save challenge for new method
				$createArgs = $WebAuthn->getCreateArgs(\hex2bin($userId), $userName, $userDisplayName, 60*4, $requireResidentKey, $userVerification, $crossPlatformAttachment);
				
				//\LoginWithAjax::update_user_meta( $user->ID, 'passkeys[challenge]', $WebAuthn->getChallenge() );
				$_SESSION['challenge'] = $WebAuthn->getChallenge();
				
				// return create args
				wp_send_json( $createArgs );
			
			} else if ($fn === 'processCreate') {
				// nonce passed, so we can assume user has permission to create a passkey (for example, via 2FA in grace mode)
				$user = $nonce_check; /* @var \WP_User $user */
				$clientDataJSON = base64_decode($post->clientDataJSON);
				$attestationObject = base64_decode($post->attestationObject);
				
				// find challenge from user ID and make sure this lines up with user that's logged in to create the
				$challenge = $_SESSION['challenge'] ?? '';
				if( empty($challenge) ) {
					wp_send_json( array( 'result' => false, 'success' => false, 'msg' => 'No challenge found for user' ) );
				}
				
				// processCreate returns data to be stored for future logins.
				// in this example we store it in the php session.
				// Normaly you have to store the data in a database connected
				// with the user name.
				$passkey = $WebAuthn->processCreate($clientDataJSON, $attestationObject, $challenge, $userVerification === 'required', true, false);
				
				// add user infos
				$userId = get_user_meta( $user->ID, 'lwa_passkey_id', true);
				$passkey->userId = $userId;
				$passkey->userName = $user->user_login;
				$passkey->userDisplayName = $user->display_name;
				
				// add browser name and OS from user agent string
				$passkey->label = 'New Device';
				
				// add create date and last used empty date
				$passkey->created = time();
				$passkey->last_used = '';
				
				// convert bin data to hex
				$passkey->AAGUID = bin2hex( $passkey->AAGUID );
				$passkey->credentialId = bin2hex( $passkey->credentialId );
				
				// save to passkeys user meta
				if ( static::update_passkey( $user->ID, $passkey ) ) {
					wp_send_json( array(
						'result' => true,
						'success' => true,
						'message' => 'Passkey was successfully registered.',
						'data' => array(
							'label' => $passkey->label,
							'last_used' => 0,
							'created' => wp_date( get_option('date_format'), $passkey->created ),
							'id' => $passkey->credentialId,
							'rpId' => $passkey->rpId,
							'multidomain' => static::is_multidomain( $user->ID ),
						)
					));
				} else {
					wp_send_json( array( 'result' => false, 'success' => false, 'error' =>  sprintf( esc_html__('Passkey could not be %s, contact support for assistance.', 'login-with-ajax-pro'), esc_html__('edited') ) ) );
				}
				
			} else if ($fn === 'getGetArgs') {
				
				$ids = array();
				if( !$requireResidentKey ) {
					$user_id = static::get_user_id( bin2hex($post->userHandle) );
					
					if( !$user_id ) {
						wp_send_json( array( 'result' => false, 'success' => false, 'error' => 'No user found for passkey' ) );
					}
					
					$passkeys = \LoginWithAjax::get_user_meta( $user_id, 'passkeys', array() );
					
					if ( count($passkeys) === 0 ) {
						throw new \Exception('no registrations for userId ' . bin2hex($post->userHandle));
					}
					
					$ids = array_keys($passkeys);
				}
				$getArgs = $WebAuthn->getGetArgs($ids, 60*4, $typeUsb, $typeNfc, $typeBle, $typeHyb, $typeInt, $userVerification);
				
				// save challange again, we may need it later
				$_SESSION['challenge'] = $WebAuthn->getChallenge();
				
				wp_send_json( $getArgs );
				
			} else if ($fn === 'processGet') {
				
				$clientDataJSON = base64_decode($post->clientDataJSON);
				$authenticatorData = base64_decode($post->authenticatorData);
				$signature = base64_decode($post->signature);
				$userHandle = base64_decode($post->userHandle);
				$id = bin2hex(base64_decode($post->id));
				$challenge = $_SESSION['challenge'] ?? '';
				$credentialPublicKey = null;
				
				$user_id = static::get_user_id( bin2hex($userHandle) );
				
				if( !$user_id ) {
					wp_send_json( array( 'result' => false, 'success' => false, 'error' => 'No user found for passkey' ) );
				}
				
				// looking up correspondending public key of the credential id, potential improvement is also validate that only ids of the given user name, although users can modify this in their browser
				$passkey = static::get_passkey( $user_id, $id );
				
				if ($passkey === null) {
					throw new \Exception('Public Key for credential ID not found!');
				}
				
				// if we have resident key, we have to verify that the userHandle is the provided userId at registration
				if ( $requireResidentKey && bin2hex($userHandle) !== $passkey->userId ) {
					throw new \Exception('User ID of passkey does not match our records.');
				}
				
				// process the get request. throws WebAuthnException if it fails
				$WebAuthn->processGet($clientDataJSON, $authenticatorData, $signature, $passkey->credentialPublicKey, $challenge, null, $userVerification === 'required');
				
				// save last-used date
				$passkey->last_used = time();
				static::update_passkey( $user_id, $passkey );
				
				// log in user
				if ( !empty($post->testing) ) {
					// this is a test request, we just return true
					wp_send_json( array( 'result' => true, 'success' => true, 'message' => esc_html__('Your passkey is successfully registered and verified!', 'login-with-ajax-pro'), 'testing' => true ) );
				} else {
					remove_all_filters('lwa_authenticate'); //allow other LWA things to authenticate and trigger 2FA
					remove_all_filters('lwa_login'); //allow other LWA things to authenticate and trigger 2FA
					remove_all_filters('lwa_ajax_2FA');
					add_filter( 'ws_plugin__s2member_login_redirect', '__return_false' );
					remove_all_filters('login_redirect');
					$user = get_user_by( 'id', $user_id );
					add_filter( 'authenticate', function( $user, $username ) { return get_user_by( 'login', $username ); }, 11, 3 );    // hook in earlier than other callbacks to short-circuit them
					$user = wp_signon( array( 'user_login' => $user->user_login, 'remember' => true ) );
					remove_all_filters( 'authenticate', 'allow_programmatic_login', 11 );
					if ( is_a( $user, 'WP_User' ) ) {
						wp_set_current_user( $user->ID, $user->user_login );
					}
					// handle redirect_to
					if( !empty($post->redirect_to) ) $_REQUEST['redirect_to'] = $post->redirect_to;
					// return login result like LWA does
					wp_send_json( \LoginWithAjax::login_result( $user ) );
				}
			} elseif ($fn === 'delete') {
				// nonce passed, so we can assume user has permission to create a passkey (for example, via 2FA in grace mode)
				$user = $nonce_check; /* @var \WP_User $user */
				// delete the passkey
				if( $user && (get_current_user_id() === $user->ID || !is_user_logged_in() || current_user_can('edit_users') ) ) {
					if( static::delete_passkey( $user->ID, $post->id ) ) {
						wp_send_json( array( 'result' => true, 'success' => true, 'message' => 'Passkey deleted.' ) );
					} else {
						wp_send_json( array( 'result' => false, 'success' => false, 'error' => sprintf( esc_html__('Passkey could not be %s, contact support for assistance.', 'login-with-ajax-pro'), esc_html__('deleted') ) ) );
					}
				} else {
					// edge case, no translation
					wp_send_json( array( 'result' => false, 'success' => false, 'error' => 'No passkey found for removal.' ) );
				}
			} elseif ($fn === 'edit') {
				// nonce passed, so we can assume user has permission to create a passkey (for example, via 2FA in grace mode)
				$user = $nonce_check; /* @var \WP_User $user */
				// update the passkey label
				if( $user && (get_current_user_id() === $user->ID || !is_user_logged_in() || current_user_can('edit_users') ) ) {
					$passkey = static::get_passkey( $user->ID, $post->id );
					if( $passkey ) {
						$passkey->label = wp_kses_data($post->label);
						if ( static::update_passkey( $user->ID, $passkey ) ) {
							wp_send_json( array( 'result' => true, 'success' => true, 'message' => 'Passkey name updated.', 'label' => $passkey->label ) );
						} else {
							wp_send_json( array( 'result' => false, 'success' => false, 'error' => sprintf( esc_html__('Passkey could not be %s, contact support for assistance.', 'login-with-ajax-pro'), esc_html__('edited') ) ) );
						}
					} else {
						// not found, edge so no translateion
						wp_send_json( array( 'result' => false, 'success' => false, 'error' => 'No passkey found for editing.') );
					}
				} else {
					// no permission, edge so no translation
					wp_send_json( array( 'result' => false, 'success' => false, 'error' => 'You do not have permission to edit this passkey.' ) );
				}
			}
			
		} catch ( \Throwable $ex) {
			wp_send_json( array('result' => false, 'success' => false, 'error' => $ex->getMessage(), 'testing' => !empty($post->testing) ) );
		}
	}
	
	/**
	 * Updates or adds a passkey to the passkeys list of given User ID
	 * @param int $user_id
	 * @param \stdClass $passkey
	 * @throws \Exception
	 *
	 * @return bool
	 */
	public static function update_passkey( $user_id, $passkey ) {
		// base64 encode it all to be safe and save so it's serializable
		$passkeys = get_user_meta( $user_id, 'lwa_passkeys', true );
		$passkeys = $passkeys ?: array();
		$current_passkey = !empty($passkeys[ $passkey->credentialId ]) ? $passkeys[ $passkey->credentialId ] : null;
		$passkeys[ $passkey->credentialId ] = $passkey;
		if( !$current_passkey ) {
			// new passkey, check there's no duplicate AAGUID
			foreach ( $passkeys as $pk ) {
				if( $pk->AAGUID === $passkey->AAGUID && $pk->credentialId !== $passkey->credentialId ) {
					if( $pk->rpId === $passkey->rpId ) {
						// only if registered for different URLs too, in case of multidomain installations
						throw new \Exception( sprintf( __('This device has already been registered as "%s".', 'login-with-ajax-pro'), $pk->label ));
					}
				}
			}
		}
		$result = update_user_meta( $user_id, 'lwa_passkeys', $passkeys );
		return $result || $current_passkey == $passkey;
	}
	
	public static function get_passkey( $user_id, $passkey_id ) {
		$passkey = null;
		$passkeys = get_user_meta( $user_id, 'lwa_passkeys', true );
		if ( !empty($passkeys[ $passkey_id ]) ) {
			$passkey = $passkeys[ $passkey_id ];
		}
		return $passkey;
	}
	
	public static function delete_passkey( $user_id, $passkey_id ) {
		// delete the passkey
		$passkeys = get_user_meta( $user_id, 'lwa_passkeys', true );
		if( !empty($passkeys[ $passkey_id ]) ) {
			unset($passkeys[ $passkey_id ]);
			update_user_meta( $user_id, 'lwa_passkeys', $passkeys );
			return true;
		}
		return false;
	}
	
	public static function get_user_id ( $userId ) {
		// find the user id from the passkey $userId
		global $wpdb;
		$sql = $wpdb->prepare('SELECT user_id FROM ' . $wpdb->usermeta . ' WHERE meta_key = "lwa_passkey_id" AND meta_value = %s', $userId);
		$user_id = $wpdb->get_var($sql);
		return $user_id;
	}
	
	/**
	 * Checks if the user has multiple passkeys with same device but registered to different domains on same site.
	 * @param $user_id
	 *
	 * @return bool
	 */
	public static function is_multidomain( $user_id ) {
		// go through passkeys and check if we have duplicate AAGUIDs for different rpIds, if so we're in multidomain mode
		$passkeys = get_user_meta( $user_id, 'lwa_passkeys', true );
		$passkeys = $passkeys ?: array();
		$multidomain = false;
		$AAGUIDs = array();
		foreach( $passkeys as $passkey ) {
			if( !empty($passkey->AAGUID) ) {
				if ( !empty( $AAGUIDs[ $passkey->AAGUID ] ) && $AAGUIDs[ $passkey->AAGUID ] !== $passkey->rpId ) {
					$multidomain = true;
					break;
				}
				$AAGUIDs[ $passkey->AAGUID ] = $passkey->rpId;
			}
		}
		return $multidomain;
	}
}
Server::init();