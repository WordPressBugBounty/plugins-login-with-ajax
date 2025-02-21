/**
 * Check if the browser supports FIDO2, Webauthn
 * @returns {Promise<boolean>}
 */
async function checkBrowserSupport() {
	let supported = false;
	if ( 'PublicKeyCredential' in window && window.PublicKeyCredential ) {
		supported = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
			.then( ( available ) => {
				return available ? true : null;
			})
			.catch((err) => {
				console.log("Could not verify Webauthn support with error : %o", err);
				return false;
			});
	}
	return supported;
}

let LWA_Passkeys = {
	get : async function( data = {} ) {
		// get check args
		let getArgs = await window.fetch(  LWA.passkeys.url.get, { method:'GET', cache:'no-cache' } ).then( data => data.json() );

		// error handling
		if (getArgs.success === false) {
			throw new Error(getArgs.error);
		}

		// replace binary base64 data with ArrayBuffer. a other way to do this
		// is the reviver function of JSON.parse()
		this.base64ToArrayBuffer(getArgs);

		// check credentials with hardware
		const cred = await navigator.credentials.get(getArgs);

		// create object for transmission to server
		let authenticatorAttestationResponse = {
			id: cred.rawId ? this.arrayBufferToBase64(cred.rawId) : null,
			clientDataJSON: cred.response.clientDataJSON  ? this.arrayBufferToBase64(cred.response.clientDataJSON) : null,
			authenticatorData: cred.response.authenticatorData ? this.arrayBufferToBase64(cred.response.authenticatorData) : null,
			signature: cred.response.signature ? this.arrayBufferToBase64(cred.response.signature) : null,
			userHandle: cred.response.userHandle ? this.arrayBufferToBase64(cred.response.userHandle) : null,
		};
		// merge data into authentiratorAttestationResponse
		authenticatorAttestationResponse = Object.assign(authenticatorAttestationResponse, data);

		// send to server
		return await window.fetch(  LWA.passkeys.url.verify, {
			method:'POST',
			body: JSON.stringify(authenticatorAttestationResponse),
			cache:'no-cache'
		}).then( data => data.json() );
	},

	create : async function() {
		// get create args
		let rep = await window.fetch( LWA.passkeys.url.create, {method:'GET', cache:'no-cache'});
		const createArgs = await rep.json();

		// error handling
		if (createArgs.success === false) {
			throw new Error(createArgs.msg || 'unknown error occured');
		}

		// replace binary base64 data with ArrayBuffer. another way to do this is the reviver function of JSON.parse()
		this.base64ToArrayBuffer(createArgs);

		// create credentials
		const cred = await navigator.credentials.create(createArgs);

		// create object
		const authenticatorAttestationResponse = {
			transports: cred.response.getTransports  ? cred.response.getTransports() : null,
			clientDataJSON: cred.response.clientDataJSON  ? this.arrayBufferToBase64(cred.response.clientDataJSON) : null,
			attestationObject: cred.response.attestationObject ? this.arrayBufferToBase64(cred.response.attestationObject) : null
		};

		// check auth on server side
		return await window.fetch( LWA.passkeys.url.register, {
			method  : 'POST',
			body    : JSON.stringify(authenticatorAttestationResponse),
			cache   : 'no-cache'
		}).then( data => data.json() );
	},

	/**
	 * convert RFC 1342-like base64 strings to array buffer
	 * @param {mixed} obj
	 * @returns {string}
	 */
	base64ToArrayBuffer : function(obj) {
		let prefix = '=?BINARY?B?';
		let suffix = '?=';
		if (typeof obj === 'object') {
			for (let key in obj) {
				if (typeof obj[key] === 'string') {
					let str = obj[key];
					if (str.substring(0, prefix.length) === prefix && str.substring(str.length - suffix.length) === suffix) {
						str = str.substring(prefix.length, str.length - suffix.length);

						let binary_string = window.atob(str);
						let len = binary_string.length;
						let bytes = new Uint8Array(len);
						for (let i = 0; i < len; i++)        {
							bytes[i] = binary_string.charCodeAt(i);
						}
						obj[key] = bytes.buffer;
					}
				} else {
					this.base64ToArrayBuffer(obj[key]);
				}
			}
		}
	},

	/**
	 * Convert a ArrayBuffer to Base64
	 * @param {ArrayBuffer} buffer
	 * @returns {String}
	 */
	arrayBufferToBase64 : function (buffer) {
		let binary = '';
		let bytes = new Uint8Array(buffer);
		let len = bytes.byteLength;
		for (let i = 0; i < len; i++) {
			binary += String.fromCharCode( bytes[ i ] );
		}
		return window.btoa(binary);
	},

	/**
	 * Handles a login
	 * @param {HTMLElement} button
	 * @returns void
	 */
	handleLogin : async function ( button ) {
		if ( !button.disabled ) {
			isLive = !button.classList.contains('test');

			let form, statusElement;
			if( isLive ) {
				let el = button.closest('.lwa-passkey-login');
				form = el.parentElement.querySelector('.lwa-form');
				if ( form === null ) {
					form = el.closest('form');
				}
				statusElement = LoginWithAJAX.addStatusElement(form);
			}
			let response = { result: false, msg: 'unknown error occured', testing : !isLive };
			let handleError = function( error ) {
				let response = { result: false, error: error.error || error.message || 'unknown error occured' };
				if( error.name && error.name === 'NotAllowedError' ) {
					response = { result: false, error: LWA.passkeys.txt.cancelled };
				}
				if( isLive ) {
					LoginWithAJAX.handleStatus(response, statusElement);
				}
			}
			try {
				if ( !button.getAttribute('data-text') ) {
					button.setAttribute('data-text', button.innerHTML);
				}
				button.innerHTML = button.getAttribute('data-text-loading');
				button.disabled = true;

				let data = {};
				if( isLive ) {
					if( form.classList.contains('lwa-form') ) {
						LoginWithAJAX.start(form);
					}
					// get redirect url if defined
					if( form.querySelector('[name="redirect_to"]') ) {
						data.redirect_to = form.querySelector('[name="redirect_to"]').value;
					}
				} else {
					data.testing = true;
				}

				await LWA_Passkeys.get( data ) .then( function( response ) {
					// check server response
					if( response.testing ) {
						alert( response.message );
					} else {
						document.dispatchEvent(new CustomEvent( 'lwa_login_passkeys', {detail: {response, form, statusElement}}) ); // trigger in vanilla js for future-proofing, devs should use this isntead
						document.dispatchEvent(new CustomEvent( 'lwa_submit_login', {detail: {response, form, statusElement}}) ); // trigger in vanilla js for future-proofing, devs should use this isntead
						if( jQuery ) {
							jQuery(document).triggerHandler('lwa_login', [response, form, statusElement]); // trigger in jQuery since that's what the rest of the plugin uses atm
						}
						LoginWithAJAX.handleStatus(response, statusElement);
					}
				}).catch( function( error ) {
					handleError(error);
				});
			} catch (error) {
				handleError(error);
			}
			if( !response.result || !isLive ) {
				button.innerHTML = button.getAttribute('data-text');
				button.disabled = false;
			}
		}
	},

	/**
	 * creates a new passkey
	 * @param {HTMLElement} button
	 * @returns void
	 */
	handleAdd : async function( button ) {
		// add loading text to button
		if ( !button.getAttribute('data-text') ) {
			button.setAttribute('data-text', button.innerHTML);
		}
		button.innerHTML = button.getAttribute('data-text-loading');
		// create new passkey
		LWA_Passkeys.create().then( response => {
			if ( response.success ) {
				// add new passkey to the list, inserting the provided dynamic text to grid list
				let table = button.closest('.lwa-passkeys-editor');
				let list = table.querySelector('ul.lwa-passkeys');
				let template = list.querySelector('li.passkey-template');
				let passkey = template.cloneNode(true);
				// show cloned item and success message
				// insert dynamic data of new passkey
				passkey.setAttribute('data-passkey-id', response.data.id);
				passkey.querySelector('div.passkey-label').innerHTML = response.data.label;
				passkey.querySelector('input.passkey-label').value = response.data.label;
				passkey.querySelector('.created-on').innerHTML = response.data.created;
				passkey.querySelector('.passkey-rpId').innerHTML = response.data.rpId;
				// add to lists, remove 'no-passkeys' message if present
				list.appendChild(passkey);
				list.querySelector('.no-passkeys').classList.add('hidden');
				passkey.querySelector('.lwa-passkey-button-edit').click();
				passkey.classList.remove('passkey-template','hidden');
				if( response.data.multidomain ) {
					list.setAttribute('data-multidomain', '1');
				}
			} else {
				alert( response.error );
			}
		}).catch( error => {
			alert( error.error || error.message || 'unknown error occured' );
		}).finally( () => {
			// reset button text
			button.innerHTML = button.getAttribute('data-text');
		});
	},

	/**
	 * Dave a passkey label
	 * @param button
	 * @returns void
	 */
	handleEdit : async function ( button ) {
		let passkey = button.closest('li');
		let list = passkey.querySelector('ul.passkeys-list');
		// add loading text to button
		if ( !button.getAttribute('data-text') ) {
			button.setAttribute('data-text', button.innerHTML);
		}
		button.innerHTML = button.getAttribute('data-text-loading');
		// save passkey label
		let response = await window.fetch( LWA.passkeys.url.edit, {
			method: 'POST',
			body: JSON.stringify({
				id: passkey.getAttribute('data-passkey-id'),
				label: passkey.querySelector('input.passkey-label').value,
				nonce: button.getAttribute('data-nonce'),
			}),
			cache: 'no-cache',
		}).then( data => data.json() );
		// update passkey label
		if ( response.result ) {
			passkey.querySelector('.passkey-label').innerHTML = response.label;
			passkey.querySelector('.passkey-editor').classList.add('hidden');
			passkey.querySelector('.passkey-info').classList.remove('hidden');
		} else {
			alert( response.error );
		}
		// reset button text
		button.innerHTML = button.getAttribute('data-text');
	},

	/**
	 * Delete a passkey from the passkeys list
	 * @param {HTMLElement} button
	 * @returns void
	 */
	handleDelete : async function ( button ) {
		let passkey = button.closest('li');
		let list = passkey.closest('ul.lwa-passkeys');
		// add loading text to button
		button.querySelector('svg.loader').classList.remove('hidden');
		button.querySelector('svg.passkey-delete-icon').classList.add('hidden');
		// delete passkey
		let response = await window.fetch( LWA.passkeys.url.delete, {
			method: 'POST',
			body: JSON.stringify({
				id: passkey.getAttribute('data-passkey-id'),
				nonce: button.getAttribute('data-nonce'),
			}),
			cache: 'no-cache',
		}).then( data => data.json() );
		// remove passkey from list
		if ( response.result ) {
			passkey.remove();
			// show 'no-passkeys' message if no passkeys left
			if ( list.querySelectorAll('li:not(.no-passkeys):not(.passkey-template)').length === 0 ) {
				list.querySelector('.no-passkeys').classList.remove('hidden');
			}
		} else {
			alert( response.error );
		}
	}
}


/**
 * event listener for login and add registration buttons
 */
document.addEventListener('click', async function( e ) {
	if( e.target.matches('button[class*="lwa-passkey-button-"]') ) {
		e.preventDefault();
		let button = e.target;
		if ( button.classList.contains('lwa-passkey-button-login') ) {
			// handle a login
			LWA_Passkeys.handleLogin( button );
		} else if ( button.classList.contains('lwa-passkey-button-delete') ) {
			// delete a passkey
			LWA_Passkeys.handleDelete( button );
		} else if ( button.classList.contains('lwa-passkey-button-add') ) {
			// register a new passkey
			LWA_Passkeys.handleAdd( button );
		} else if ( button.classList.contains('lwa-passkey-button-edit-save') ) {
			// save label of passkey
			LWA_Passkeys.handleEdit( button );
		} else if ( button.classList.contains('lwa-passkey-button-edit') ) {
			// show edit form, no function needed
			let passkey = button.closest('li');
			let list = passkey.closest('ul.lwa-passkeys');
			list.querySelectorAll('.passkey-editor').forEach( el => el.classList.add('hidden') );
			list.querySelectorAll('.passkey-info').forEach( el => el.classList.remove('hidden') );
			passkey.querySelector('.passkey-editor').classList.remove('hidden');
			passkey.querySelector('.passkey-info').classList.add('hidden');
			passkey.querySelector('.passkey-editor input').focus();
		} else if ( button.classList.contains('lwa-passkey-button-edit-cancel') ) {
			// show edit form, no function needed
			let passkey = button.closest('li');
			passkey.querySelector('.passkey-editor').classList.add('hidden');
			passkey.querySelector('.passkey-info').classList.remove('hidden');
		}
	}

});

let lwa_passkeys_init = function ( container ) {
	// move div to bottom of wp login panel form if browser supports passkeys
	let showSupportWarning = function( className = 'not-supported' ) {
		container.querySelectorAll('.lwa-passkey-login .'+className).forEach(el => {
			el.classList.remove('hidden');
		});
		container.querySelectorAll('.lwa-passkey-login .lwa-passkey-button-login').forEach( button => {
			button.disabled = true;
		});
	}
	if ( !window.fetch || !navigator.credentials || !navigator.credentials.create ) {
		showSupportWarning('not-supported');
	} else {
		if ( 'PublicKeyCredential' in window && window.PublicKeyCredential ) {
			window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
				.then((available) => {
					if ( !available ) {
						// show not supported messages
						showSupportWarning('not-fully-supported');
					}
				})
				.catch((err) => {
					// Something went wrong
					showSupportWarning('not-supported');
					console.error(err);
				});
		} else {
			showSupportWarning('not-supported');
		}
	}
	// show passkey login form
	container.querySelectorAll('.lwa-passkey-login').forEach(el => {
		el.classList.remove('hidden');
		let form = el.closest('form');
		form.append(el);
	});
};

// load passkeys if supported or show support warning
document.addEventListener('lwa_loaded', async function() {
	lwa_passkeys_init( document );
});

// listen for 2FA verified hook
document.addEventListener('lwa_submit_login', function( e ){
	if ( e.detail.response.result && 'passkeys' in e.detail.response ) {
		LWA.passkeys.url = e.detail.response.passkeys.url;
	}
});

// listen for lwa_2FA_setup_init hook
document.addEventListener('lwa_2FA_setup_init', function( e ){
	lwa_passkeys_init( e.detail.container );
});