from fido2.hid import CtapHidDevice
from fido2.ctap2.base import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.ctap import CtapError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import json
import hashlib
import base64
import getpass
import socket
import os

from .admin import _random, _suuid
from .handlers import _error, _nf_warn, _debug, _success

class U2FKey:
    def __init__(self, mappings_file: str | None = None, rp_id: str | None = None, use_pin: bool = False, secrets_dir: str = ".d/terces"):
        self.mappings_file: str = mappings_file or '/etc/u2f_mappings' # sane fallback
        self.rp_id: str = rp_id or f"pam://{socket.gethostname()}"
        self.use_pin: bool = use_pin
        self.secrets_dir: str = secrets_dir
        self.secrets_index: str = f"{self.secrets_dir}/_tm.json"

    def check_perms(self):
        self.perms = oct(os.stat(self.mappings_file).st_mode)[-3:]
        perms = int(self.perms)  # Convert octal string to int
        _debug(f'Perms {perms} for {self.mappings_file}')
        if perms > 600:
            _nf_warn("Key permissions unsufficient.")
            return False
        return True

    def get_device(self):
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            _nf_warn("No key: Press ENTER to retry or CTRL+C to cancel.")
            input()
            return self.get_device()  # Just go back to top
        return devices[0] # Currently only support first key found
    
    def load_key_handle(self) -> str:
        try:
            with open(self.mappings_file) as f:
                return f.read().split(':')[1].split(',')[0] # defaultt mappings format
        except PermissionError:
                _error("Keyfile is probably owned by root or other user. Use sudo or doas.")
                raise

    def authenticate(self) -> bool:
        assertion = None
        dev = self.get_device()
        ctap = Ctap2(dev)

        key_handle = self.load_key_handle()
        client_data_hash = hashlib.sha256(b"challenge").digest()

        try:
            if self.use_pin:
                client_pin = ClientPin(ctap)

                retries = client_pin.get_pin_retries()
                _debug(f"PIN/Biometrics retries remaining: {retries}")
                pin = getpass.getpass("Enter PIN: ")
                pin_token = client_pin.get_pin_token(pin)
                pin_auth = client_pin.protocol.authenticate(pin_token, client_data_hash)

                print("Touch security key...")
                assertion = ctap.get_assertion(
                    self.rp_id,
                    client_data_hash,
                    [{"type": "public-key", "id": base64.b64decode(key_handle)}],
                    pin_uv_param=pin_auth,
                    pin_uv_protocol=client_pin.protocol.VERSION
                )
                _debug(f"Got assertion with counter: {assertion.auth_data.counter}")

            else:
                print("Touch Security Key...")
                assertion = ctap.get_assertion(
                    self.rp_id,
                    client_data_hash,
                    [{"type": "public-key", "id": base64.b64decode(key_handle)}]
                )

        except CtapError as e:
            if e.code == CtapError.ERR.PIN_INVALID:
                _error("Incorrect PIN")
            else:
                _error(f"Authentication error: {e}")

        #print(assertion)
        # example results
        #id; type
        #auth-data: rp_id_hash, flags, counter, credentials data, extensions
        # signature, user, nbr of creds, user selected, large blob key

        return assertion is not None

    def get_terces(self, salt: bytes, pin_token=None) -> bytes:
        """
        Derive a deterministic secret from the FIDO2 authenticator using hmac-secret extension.

        The hmac-secret extension allows deriving secrets that are:
        - Bound to a specific credential (key_handle)
        - Deterministic given the same salt
        - Never exposed - the authenticator performs HMAC-SHA256 internally

        Flow (per CTAP2 spec):
        1. Platform gets key agreement from authenticator (ECDH public key)
        2. Platform generates ephemeral keypair and computes shared secret via ECDH
        3. Salt is encrypted with shared secret and sent to authenticator
        4. Authenticator decrypts salt, computes HMAC-SHA256(credential_secret, salt)
        5. Result is encrypted with shared secret and returned to platform

        Args:
            salt: Application-specific salt (will be padded/truncated to 32 bytes)
            pin_token: Optional pre-obtained PIN token to avoid re-prompting

        Returns:
            32-byte deterministic secret derived from credential + salt
        """
        dev = self.get_device()
        ctap = Ctap2(dev)
        client_pin = ClientPin(ctap)

        # Get fresh PIN token with GET_ASSERTION permission (required for CTAP2.1/V2)
        # Tokens are scoped to specific permissions and RP ID for protocol V2
        if pin_token is None:
            retries = client_pin.get_pin_retries()
            _debug(f"PIN/Biometrics retries remaining: {retries}")
            pin = getpass.getpass("Enter PIN: ")
            pin_token = client_pin.get_pin_token(
                pin,
                permissions=ClientPin.PERMISSION.GET_ASSERTION,
                permissions_rpid=self.rp_id
            )

        # Get shared secret using ClientPin's internal method (handles V1/V2 properly)
        # This performs key agreement with the authenticator and derives the shared secret
        # _get_shared_secret() returns (platform_key_agreement, shared_secret)
        platform_key_agreement, shared_secret = client_pin._get_shared_secret()

        # Salt must be exactly 32 bytes (or 64 for two salts)
        salt_padded = salt.ljust(32, b'\x00')[:32]

        # Encrypt salt using PinProtocol's encrypt method
        # - V2: AES-256-CBC with random IV prepended (key = shared_secret[32:])
        salt_enc = client_pin.protocol.encrypt(shared_secret, salt_padded)

        # Authenticate encrypted salt (HMAC for integrity)
        # Protocol.authenticate() returns correct length V2 (32 bytes)
        salt_auth = client_pin.protocol.authenticate(shared_secret, salt_enc)

        # Build hmac-secret extension input per CTAP2 spec
        hmac_secret_params = {
            1: platform_key_agreement,       # keyAgreement (COSE_Key)
            2: salt_enc,                     # saltEnc (encrypted 32 or 64 byte salt)
            3: salt_auth,                    # saltAuth (first 16 bytes of HMAC)
            4: client_pin.protocol.VERSION,  # pinUvAuthProtocol (required for V2)
        }

        key_handle = self.load_key_handle()
        client_data_hash = hashlib.sha256(b"challenge").digest()

        # PIN auth for the assertion itself (uses pin_token, NOT shared_secret)
        pin_auth = client_pin.protocol.authenticate(pin_token, client_data_hash)

        print("Touch Security Key...")

        try:
            assertion = ctap.get_assertion(
                self.rp_id,
                client_data_hash,
                [{"type": "public-key", "id": base64.b64decode(key_handle)}],
                extensions={"hmac-secret": hmac_secret_params},
                pin_uv_param=pin_auth,
                pin_uv_protocol=client_pin.protocol.VERSION
            )
        except CtapError as e:
            _error(f"{e}")
            raise

        _debug(f"Got assertion with counter: {assertion.auth_data.counter}")

        # Decrypt the hmac-secret output using protocol's decrypt method
        # The authenticator returns: AES_encrypt(shared_secret, HMAC-SHA256(cred_secret, salt))
        if assertion.auth_data.extensions and 'hmac-secret' in assertion.auth_data.extensions:
            output_enc = assertion.auth_data.extensions['hmac-secret']
            secret = client_pin.protocol.decrypt(shared_secret, output_enc)
            return secret[:32]

        _error("No hmac-secret in response")
        raise RuntimeError("No hmac-secret extension in assertion response")

    def _load_index(self) -> dict:
        """Load the name->UUID mapping"""
        if os.path.exists(self.secrets_index):
            with open(self.secrets_index) as f:
                return json.load(f)
        return {}
    
    def _save_index(self, index: dict):
        """Save the name->UUID mapping"""
        os.makedirs(self.secrets_dir, exist_ok=True)
        with open(self.secrets_index, "w") as f:
            json.dump(index, f, indent=2)

    def _derive_filename(self, name: str) -> str:
        """
        Derive filename from name + credential-specific salt.
        Using key_handle as salt: each FIDO2 credential is unique, so
        hash(key_handle + name) produces different filenames per user/key.
        Attacker needs both the name AND access to your specific key_handle.
        Default lockout on keys is 8 attempts and can be up to 63 mixed chars.
        Good luck ! 
        """
        salt = self.load_key_handle()
        secret_id = hashlib.sha256((salt + name).encode()).hexdigest()[:16]
        return f"{self.secrets_dir}/{secret_id}.enc"

    def encrypt_secret(self, name: str, plaintext: str | bytes, description: str = "") -> str:
        """Encrypt a secret using salted name-derived filename"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        key = self.get_terces(name.encode())
        nonce = _random(12)
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)

        filename = self._derive_filename(name)
        os.makedirs(self.secrets_dir, exist_ok=True)

        with open(filename, "wb") as f:
            f.write(nonce + ciphertext)

        # Optional log for user reference # NOT REQUIRED for decryption totally optional
        from datetime import datetime
        log = self._load_index()
        log[_suuid()] = {"description": description, "time": datetime.now().isoformat()}
        self._save_index(log)

        _success(f"Secret encrypted: {name}")
        return filename

    def decrypt_secret(self, name: str) -> str | None:
        """Decrypt a secret using salted name-derived filename"""
        filename = self._derive_filename(name)

        if not os.path.exists(filename):
            _error(f"No secret found for: {name}")
            return None

        key = self.get_terces(name.encode())

        with open(filename, "rb") as f:
            data = f.read()

        nonce, ciphertext = data[:12], data[12:]
        cipher = AESGCM(key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)

        return plaintext.decode()