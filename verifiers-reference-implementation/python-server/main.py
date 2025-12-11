'''
Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

"""
Flask application to process and verify identity tokens from Google Wallet
using the 'openid4vp' protocols.
"""

# Standard Library Imports
import base64
import hashlib
import json
import os
import requests

# Third-Party Imports
import cbor2                                # For CBOR encoding/decoding
from flask import Flask, request, jsonify, render_template  # For the web application framework
from isomdoc import verify_device_response  # For mdoc/mDL verification (ISO 18013-5)
from jwcrypto import jwe, jwk               # For JSON Web Encryption (JWE) handling in OpenID4VP

# --- Configuration ---

# TODO: Replace with your actual application's package name (for Android)
# Used in constructing the SessionTranscript for the 'preview' protocol.
APP_PACKAGE_NAME = "<your_app_package_name>"

# URL for the external Zero-Knowledge Verifier service's verification endpoint.
ZK_VERIFIER_URL = "<path_to_ZKverifier>/zkverify"
# URL for the external Zero-Knowledge Verifier service's specifications endpoint.
SPECS_URL = "<path_to_ZKverifier>/specs"

# TODO: Replace with the actual SHA-256 hash of your Android app's signing certificate
# Used in constructing the SessionTranscript for the 'openid4vp' protocol when
# the origin is an Android app. Find using:
# keytool -printcert -jarfile your_app.apk | grep SHA256 | awk '{print $2}' | xxd -r -p | sha256sum | awk '{print $1}'
ANDROID_APP_SIGNATURE_HASH = "<your_app_signature_here_without_':'>"

# JWE Configuration for OpenID4VP (Constants for clarity)
JWE_ALG = "ECDH-ES"  # Key Agreement Algorithm
JWE_ENC = "A128GCM"  # Content Encryption Algorithm
# --- Protocol Definitions ---
# A list of all supported OpenID4VP protocols.
openid4vp_protocols = ["openid4vp-v1-unsigned", "openid4vp-v1-signed"]

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Helper Functions ---

def generate_secure_nonce(length_bytes: int = 32) -> tuple[bytes, str]:
    """
    Generates a cryptographically secure random nonce.

    Args:
        length_bytes: The desired length of the nonce in bytes.

    Returns:
        A tuple containing:
            - raw_nonce (bytes): The raw nonce bytes.
            - base64_nonce_unpadded (str): The URL-safe base64 encoded nonce string, without padding.
    """
    raw_nonce = os.urandom(length_bytes)
    # Encode and remove potential '=' padding for compatibility where needed
    base64_nonce_unpadded = base64.urlsafe_b64encode(raw_nonce).decode("utf-8").rstrip("=")
    return raw_nonce, base64_nonce_unpadded

def encode_key_base64(key_bytes: bytes) -> str:
    """Encodes key bytes into URL-safe base64 string without padding."""
    return base64.urlsafe_b64encode(key_bytes).decode("utf-8").rstrip("=")

def decode_base64_key(key_base64_unpadded: str) -> bytes:
    """
    Decodes a URL-safe base64 encoded key string, adding padding if necessary.

    Args:
        key_base64_unpadded: The base64 string, potentially without padding.

    Returns:
        The decoded bytes.

    Raises:
        binascii.Error: If the base64 string is invalid.
    """
    # Calculate and add the required padding for correct decoding.
    padding = "=" * (4 - (len(key_base64_unpadded) % 4))
    return base64.urlsafe_b64decode(key_base64_unpadded + padding)

# The following method is only for illustration, state array will not be required in production. 
# you are expected to create keys and store them in your database. Use the stored keys for authentication.
# Don't pass private keys in request.
def generate_request_state() -> dict:
    """
    Generates the necessary state for initiating a credential request.

    This includes generating a nonce in its base64 (unpadded) form.

    Returns:
        A dictionary containing the generated state:
        {
            "nonce_base64": str,             # URL-safe base64 encoded nonce (no padding)
            # "jwe_private_key_jwk": str (added later only for openid4vp)
        }
    """
    # 1. Generate Nonce
    _, nonce_base64 = generate_secure_nonce(32)
    print(f"Generated Nonce (Base64, unpadded): {nonce_base64}") # Keep for debugging/demo



    # 2. Store in state dictionary
    state = {
        "nonce_base64": nonce_base64,
    }
    return state


def construct_openid4vp_request(doctypes: list[str], requested_fields: list[dict], nonce_base64: str, jwe_encryption_public_jwk: jwk.JWK, is_zkp_request: bool, is_signed_request: bool) -> dict:
    """
    Constructs the request dictionary for the OpenID4VP protocol.

    Args:
        doctypes: A list of document types being requested (e.g., ["org.iso.18013.5.1.mDL"]).
        requested_fields: A list of dictionaries specifying requested fields.
                          Format: [{"namespace": str, "name": str}, ...].
        nonce_base64: The URL-safe base64 encoded nonce (padding removed).
        jwe_encryption_public_jwk: The reader's public JWK for response encryption.
        is_zkp_request : Boolean for getting a ZKP.
        is_signed_request: Flag to indicate if the request is signed.

    Returns:
        A dictionary representing the OpenID4VP request structure.
    """
    
    credentials_list = []
    credential_set_options = []
    # Define claims once, as they can be applied to multiple credential types but you might change it if you need different elements.
    claims_list = []
    for field_data in requested_fields:
        claim = {
            "path": [field_data["namespace"], field_data["name"]], # Path to the claim within the mdoc
            "intent_to_retain": False # set this to true if you are saving the value of the field
        }
        claims_list.append(claim)
    # Create a credential request for each doctype
    for i, doctype in enumerate(doctypes):
        # Generate a unique ID for each credential request for traceability
        # e.g., "mdl-request" or "idcard-request"
        request_id = f"{doctype.split('.')[-1].lower()}-request"
        meta = {"doctype_value": doctype}
        format_type = "mso_mdoc"
        
        if is_zkp_request:
            zk_system_type, error = fetch_and_process_specs(len(requested_fields))
            if error:
                return error  # Propagate error
            meta["zk_system_type"] = zk_system_type
            meta["verifier_message"] = "challenge"
            format_type = "mso_mdoc_zk"

        credential_request = {
            "id": request_id,
            "format": format_type,
            "meta": meta
        }
        
        # Add claims if any were requested
        if claims_list:
            credential_request["claims"] = claims_list
            
        credentials_list.append(credential_request)
        # Each option is a list containing one request ID, creating an OR condition
        # e.g., [[ "mdl-request" ], [ "id_pass-request" ]]
        credential_set_options.append([request_id])

    # Define the credential query using DCQL (Digital Credential Query Language - conceptual)
    dcql_query = {
        "credentials": credentials_list,
        "credential_sets" : [
            {
                "options": credential_set_options
            }
        ]
    }

    

    # Client metadata describing how the response should be encrypted
    client_metadata = {
        "jwks": {"keys": [jwe_encryption_public_jwk.export(private_key=False, as_dict=True)]},
    }

    # The 'mdoc_crypto_capabilities' object specifies the cryptographic algorithms
    # supported by the verifier for the mdoc (Mobile Document) format.
    # This is part of the OpenID4VP standard and communicates the verifier's
    # capabilities to the wallet, ensuring that the response is signed and
    # encrypted with a mutually understood algorithm.
    # '-7' corresponds to ES256 (ECDSA with P-256 and SHA-256), a common
    # algorithm for signing and authentication in this context.
    mdoc_crypto_capabilities = {
        "mso_mdoc":{
            "isserauth_alg_values":[-7],
            "deviceauth_alg_values":[-7]
        }
    }
    client_metadata ["vp_formats_supported"] = mdoc_crypto_capabilities

    # Construct the main OpenID4VP request payload
    request_payload = {
        "response_type": "vp_token",   # Requesting a Verifiable Presentation Token
        "response_mode": "dc_api.jwt", # Response delivered via DeviceCheck API as JWT,
        "nonce": nonce_base64,         # Nonce (must match state) - note base64 without padding
        "dcql_query": dcql_query,      # The credential query
        "client_metadata": client_metadata # How the client wants the response encrypted
    }
    return request_payload


def fetch_and_process_specs(num_attributes):
    """
    Fetches specs from the SPECS_URL, filters them by the number of attributes,
    identifies the top two latest versions from the filtered list,
    and returns the specs for those versions.

    This function is designed to be reusable across different parts of a server.

    Args:
        num_attributes (int): The number of attributes to filter the specs by.

    Returns:
        tuple: A tuple containing two elements:
               - A list of specs (list) if successful, otherwise None.
               - A dictionary containing error details (dict) if an error occurred, otherwise None.
    """
    try:
        # Make a GET request to the external specs endpoint
        # NOTE: 'requests' library needs to be imported for this to work.
        response = requests.get(SPECS_URL)
        
        # Raise an exception for bad status codes (4xx or 5xx)
        response.raise_for_status()
        
        # Parse the JSON response into a Python list of dictionaries
        all_specs = response.json()
        
        # If no specs are returned, exit gracefully
        if not all_specs:
            return [], None # Return empty list and no error

        # --- Filter by num_attributes first ---
        specs_for_attributes = [
            spec for spec in all_specs if spec.get('num_attributes') == num_attributes
        ]
        
        # If no specs match the attribute count, exit gracefully
        if not specs_for_attributes:
            return [], None # No specs found for this num_attributes

        # --- Logic to find the top two versions from the filtered list ---
        
        # 1. Get all unique version numbers from the filtered list of specs
        unique_versions = set(spec['version'] for spec in specs_for_attributes)
        
        # 2. Sort the unique versions in descending order to find the latest ones
        sorted_versions = sorted(list(unique_versions), reverse=True)
        
        # 3. Get the top two latest versions.
        top_two_versions = sorted_versions[:2]
        
        # --- Filter the specs based on the top two versions ---
        
        # Filter the already attribute-filtered list for the top versions.
        latest_specs = [
            spec for spec in specs_for_attributes if spec.get('version') in top_two_versions
        ]
        
        # Return the data and None for the error part of the tuple
        return latest_specs, None

    except requests.exceptions.RequestException as e:
        # Handle network errors and return None for data and the error details
        error_details = {"error": "Could not connect to the specs service.", "details": str(e)}
        return None, error_details
    except ValueError as e:
        # Handle JSON decoding errors
        error_details = {"error": "Failed to decode JSON from the specs service.", "details": str(e)}
        return None, error_details
    except Exception as e:
        # Handle any other unexpected errors
        error_details = {"error": "An unexpected error occurred.", "details": str(e)}
        return None, error_details


def extract_data_from_mdoc(verified_mdoc_data) -> list[dict] | None:
    """
    Extracts the disclosed element values from a verified mdoc structure
    (returned by isomdoc.verify_device_response).

    Args:
        verified_mdoc_data: The data structure returned by isomdoc.verify_device_response.
                            Expected to have a `documents` attribute.

    Returns:
        A list of dictionaries containing disclosed data elements
        [{"name": element_identifier, "value": element_value}, ...],
        or None if parsing fails or no documents are found.
    """
    extracted_data = []
    try:
        # The structure comes from the isomdoc library's parsing
        documents = verified_mdoc_data.documents
        if not documents:
            print("No documents found in verified mdoc data.")
            return [] # Return empty list if no documents present

        # Loop through each document in the verified data
        for doc in documents:
            # Access namespaces within the IssuerSigned structure
            issuer_signed_data = doc.issuer_signed
            namespaces = issuer_signed_data.namespaces # dict: {namespace_str: [Element, ...]}

            # Loop through namespaces to get disclosed elements
            for namespace_id, elements in namespaces.items():
                if elements is None: # Should not happen with valid data, but check
                    print(f"Warning: Namespace {namespace_id} has None elements.")
                    continue
                for element in elements:
                    # Add the disclosed element to our list
                    if isinstance(element.element_value, cbor2.CBORTag):
                        element.element_value = element.element_value.value
                    if isinstance(element.element_value, bytes):
                        extracted_data.append(
                            {"name": element.element_identifier, "value": base64.urlsafe_b64encode(element.element_value).decode('utf-8').rstrip("=")}
                        )
                    else:
                        extracted_data.append({
                            "name": element.element_identifier,
                            "value": element.element_value,
                        })
        return extracted_data
    except AttributeError as e:
        # Handle cases where the data structure is not as expected
        print(f"Error parsing verified mdoc data structure: {e}. Data: {verified_mdoc_data}")
        return None # Indicate failure due to unexpected structure
    except Exception as e:
        # Catch any other unexpected errors during extraction
        print(f"Unexpected error during mdoc data extraction: {e}")
        return None


def generate_openid4vp_session_transcript(client_id: str, nonce_base64_unpadded: str, origin_info: str, encryption_public_jwk_thumbprint: str) -> list:
    """
    Generates the SessionTranscript structure (as a Python list) required for mdoc
    verification when using the OpenID4VP handover mechanism.

    Ref: ISO/IEC 18013-5:2021, Annex D (informative) D.4.2.2, mdoc session transcript

    Args:
        client_id: The client identifier (e.g., "web-origin:https://example.com" or "android-origin:com.example.app").
        nonce_base64_unpadded: The URL-safe base64 encoded nonce (no padding) used in the request.
        origin_info: The origin information string (e.g., "https://example.com" or "android:apk-key-hash:<hash>").
        encryption_public_jwk_thumbprint: The thumbprint of the reader's public JWK for response encryption.

    Returns:
        A list representing the CBOR SessionTranscript structure.
    """
    handover_data = None
    encryption_public_jwk_thumbprint = decode_base64_key(encryption_public_jwk_thumbprint)
    handover_data = [
        origin_info,
        nonce_base64_unpadded, # Use the unpadded nonce consistent with request
        encryption_public_jwk_thumbprint
    ]
    # print(f"OpenID4VP Handover Data for Hashing: {handover_data}") # Debugging

    # Hash the handover data using SHA-256
    handover_bytes_hash = hashlib.sha256(cbor2.dumps(handover_data)).digest()
    # print(f"OpenID4VP Handover Hash (Hex): {handover_bytes_hash.hex()}") # Debugging

    # Construct the SessionTranscript array for mdoc verification according to ISO 18013-5 spec
    session_transcript_list = [
        None, 
        None,  
        [ # Element 2: Handover (identifies protocol and binds request)
            "OpenID4VPDCAPIHandover", # Identifies the handover mechanism
            handover_bytes_hash       # The hash calculated above
        ]
    ]
    return session_transcript_list

def process_openid4vp_response(encrypted_jwe_string: str, request_state: dict, origin: str, is_signed_request: bool) -> list[dict] | None:
    """
    Processes an encrypted OpenID4VP response (JWE received via direct_post.jwt).

    Steps:
    1. Extracts the JWE string from the payload.
    2. Decrypts the JWE using the reader's private key stored in the state.
    3. Extracts the base64 encoded mdoc data (vp_token).
    4. Constructs the appropriate OpenID4VP SessionTranscript.
    5. Verifies the mdoc signature and structure using the SessionTranscript.
    6. (this step is not covered here) Verify the issuer against the issuer certs to trust the data authenticity.
    7. Extracts the disclosed credential data.

    Args:
        encrypted_jwe_string: expected to contain a 'response' key holding the
                              JWE string.
        request_state: The state dictionary generated during the request phase,
                       containing the nonce and the JWE private key.
        origin: The origin string (URL or Android package info) used in the request.
        is_signed_request: Flag that indicates if the request is signed.

    Returns:
        A list of extracted credential data dictionaries, or None if processing fails.
    """
    try:
        #1. Retrieve necessary state items
        nonce_base64_unpadded = request_state.get("nonce_base64")
        jwe_private_key_json_str = request_state.get("jwe_private_key_jwk") # Expecting JSON string
        if not nonce_base64_unpadded or not jwe_private_key_json_str:
             print("Error: Missing 'nonce_base64' or 'jwe_private_key_jwk' in request state.")
             return None

        # Load the reader's private key from its JSON representation
        reader_private_jwk = jwk.JWK.from_json(jwe_private_key_json_str)
        encryption_public_jwk_thumbprint = reader_private_jwk.thumbprint()

        # 2. Decrypt the JWE
        jwe_object = jwe.JWE()
        jwe_object.deserialize(encrypted_jwe_string)
        jwe_object.decrypt(reader_private_jwk)
        decrypted_payload_bytes = jwe_object.payload
        decrypted_data = json.loads(decrypted_payload_bytes)
        # print(f"Decrypted OpenID4VP Payload: {decrypted_data}") # Debugging
        
        # 3. Extract the Verifiable Presentation Token (containing the mdoc)
        # The structure depends on the wallet's implementation of vp_token response.
        # Common structure: vp_token = { "presentation_submission": {...}, "vp": "encoded_mdoc_or_jwt" }
        # With the new request format, the mdoc is keyed by the dynamic request ID
        # (e.g., "mdl-request"). We need to find it dynamically.
        vp_token_structure = decrypted_data.get("vp_token", {}) # Assuming vp_token holds the result

        # The key for the mdoc data will match one of the 'id' fields from the request.
        # Since the wallet returns only one fulfilled credential, we find the first
        # string value in the vp_token dictionary, which should be the encoded mdoc.
        encoded_mdoc_data = None
        if isinstance(vp_token_structure, dict):
            for credential_key,encoded_mdoc_data in vp_token_structure.items():
                if isinstance(encoded_mdoc_data, list): # OpenID4VP 1.0 requires every credential response to be a list.
                    encoded_mdoc_data = encoded_mdoc_data[0]
        # Fallback for simpler responses where the vp_token itself is the encoded string
        if not encoded_mdoc_data and isinstance(vp_token_structure, str):
             encoded_mdoc_data = vp_token_structure

        if not encoded_mdoc_data or not isinstance(encoded_mdoc_data, str):
            print("Error: Could not find encoded mdoc data in decrypted payload.")
            print(f"Decrypted data structure: {decrypted_data}")
            return None

        # Decode the base64 mdoc data (add padding if needed)
        try:
            mdoc_bytes = decode_base64_key(encoded_mdoc_data)
        except Exception as e:
            print(f"Error decoding base64 mdoc data: {e}")
            return None

        # 4. Construct SessionTranscript based on origin
        if origin.startswith("https://") or origin.startswith("http://"): # Web Origin
            client_id = f"web-origin:{origin}"
            origin_info = origin
            session_transcript_list = generate_openid4vp_session_transcript(
                client_id, nonce_base64_unpadded, origin_info, encryption_public_jwk_thumbprint
            )
        else: # Assume Android Origin
            client_id = f"android-origin:{APP_PACKAGE_NAME}"
            # Calculate the base64 encoded SHA256 hash of the app signing cert
            try:
                app_signature_hash_bytes = bytes.fromhex(ANDROID_APP_SIGNATURE_HASH)
                app_signature_hash_base64 = base64.b64encode(app_signature_hash_bytes).decode("utf-8").rstrip("=")
                origin_info = f"android:apk-key-hash:{app_signature_hash_base64}"
                session_transcript_list = generate_openid4vp_session_transcript(
                    client_id, nonce_base64_unpadded, origin_info, encryption_public_jwk_thumbprint
                )
            except ValueError as e:
                print(f"Error processing Android signature hash: {e}. Ensure ANDROID_APP_SIGNATURE_HASH is correct hex.")
                return None

        # print(f"Using Session Transcript (List) for Verification: {session_transcript_list}") # Debugging

        # 5. Verify the mdoc using isomdoc library
        # This checks signature, chain of trust (if CAs provided), and validity.
        # It uses the SessionTranscript to bind the response to the request context.
        # TODO: Add trusted CA certificates to verify_device_response for production trust chain validation.
        # Example: verified_mdoc = verify_device_response(mdoc_bytes, session_transcript_list, trusted_ca_certs=[...])
        verified_mdoc_data = verify_device_response(mdoc_bytes, session_transcript_list)
        print("MDOC Verification Successful (isomdoc)") # Confirmation message

        # 7. Extract disclosed data
        credential_data = extract_data_from_mdoc(verified_mdoc_data)
        # credential_data will be None if extraction failed, or a list (possibly empty) if successful.
        return credential_data # Return the list or None

    except jwe.InvalidJWEData as e:
        print(f"Error decrypting/processing JWE: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON payload inside JWE: {e}")
        return None
    except KeyError as e:
        print(f"Error accessing key in state or decrypted data: {e}")
        return None
    except Exception as e:
        # Catch-all for other unexpected errors during processing
        print(f"Unexpected error processing OpenID4VP response: {e}")
        # Consider logging the traceback here for debugging
        # import traceback; traceback.print_exc()
        return None


def process_openid4vp_zk_response(encrypted_jwe_string: str, request_state: dict, origin: str, is_signed_request: bool) -> dict | None:
    """
    Processes an OpenID4VP response, prepares it for Zero-Knowledge (ZK)
    verification, sends it to an external verifier, and processes the result.

    Steps:
    1.  Decrypts the JWE payload received from the wallet.
    2.  Extracts the mdoc (Mobile Driving License) data.
    3.  Constructs the OID4VP Session Transcript based on the request origin.
    4.  Encodes the mdoc data and Session Transcript into the format required
        by the ZK verification server.
    5.  Sends the data to the ZK verification server via a secure POST request.
    6.  Parses the verification server's response and returns the claims or error.

    Args:
        encrypted_jwe_string: The encrypted JWE string from the OpenID4VP response.
        request_state: The state dictionary from the request phase, containing the
                       nonce and the reader's private JWE key.
        origin: The origin string (URL or Android package info) of the request.
        is_signed_request: Flag that indicates if the request is signed.

    Returns:
        A dictionary containing the verification result.
        - On success: {"status": True, "claims": [{"identifier": "...", "value": ...}]}
        - On failure: {"status": False, "message": "Error description"}
        Returns None if a critical error occurs before contacting the server.
    """
    try:
        # 1. Retrieve necessary items from the request state
        nonce_base64_unpadded = request_state.get("nonce_base64")
        jwe_private_key_json_str = request_state.get("jwe_private_key_jwk")
        if not nonce_base64_unpadded or not jwe_private_key_json_str:
            print("Error: Missing 'nonce_base64' or 'jwe_private_key_jwk' in request state.")
            return None
        
        # Load the reader's private key
        reader_private_jwk = jwk.JWK.from_json(jwe_private_key_json_str)
        encryption_public_jwk_thumbprint = reader_private_jwk.thumbprint()

        # 2. Decrypt the JWE to get the wallet's response
        jwe_object = jwe.JWE()
        jwe_object.deserialize(encrypted_jwe_string)
        jwe_object.decrypt(reader_private_jwk)
        decrypted_payload_bytes = jwe_object.payload
        decrypted_data = json.loads(decrypted_payload_bytes)

        # 3. Extract the Verifiable Presentation Token (containing the mdoc)
        # The structure depends on the vp_token containing the encoded mdoc data
        vp_token_structure = decrypted_data.get("vp_token", {})

        # The key for the mdoc data will match one of the 'id' fields from the request.
        # Since the wallet returns only one fulfilled credential, we find the first
        # string value in the vp_token dictionary, which should be the encoded mdoc.
        encoded_mdoc_data = None
        if isinstance(vp_token_structure, dict):
            for credential_key,encoded_mdoc_data in vp_token_structure.items():
                if isinstance(encoded_mdoc_data, list): # OpenID4VP 1.0 requires every credential response to be a list.
                    encoded_mdoc_data = encoded_mdoc_data[0]
        # Fallback for simpler responses where the vp_token itself is the encoded string
        if not encoded_mdoc_data and isinstance(vp_token_structure, str):
             encoded_mdoc_data = vp_token_structure

        if not encoded_mdoc_data or not isinstance(encoded_mdoc_data, str):
            print("Error: Could not find encoded mdoc data in decrypted payload.")
            return None

        # Decode the base64url-encoded mdoc data
        try:
            device_response_bytes = decode_base64_key(encoded_mdoc_data)
        except Exception as e:
            print(f"Error decoding base64 mdoc data: {e}")
            return None

        # 4. Construct the Session Transcript required for verification
        if origin.startswith("https://") or origin.startswith("http://"):
            client_id = f"web-origin:{origin}"
            origin_info = origin
        else: # Assume Android Origin
            client_id = f"android-origin:{APP_PACKAGE_NAME}"
            try:
                app_signature_hash_bytes = bytes.fromhex(ANDROID_APP_SIGNATURE_HASH)
                app_signature_hash_base64 = base64.b64encode(app_signature_hash_bytes).decode("utf-8")
                origin_info = f"android:apk-key-hash:{app_signature_hash_base64}"
            except ValueError as e:
                print(f"Error processing Android signature hash: {e}")
                return None

        session_transcript = generate_openid4vp_session_transcript(
            client_id, nonce_base64_unpadded, origin_info, encryption_public_jwk_thumbprint
        )

        # 5. Prepare the payload for the ZK verification server
        # The server expects the device response and transcript as base64-encoded CBOR
        device_response_b64 = base64.b64encode(device_response_bytes).decode("utf-8")
        session_transcript_cbor = cbor2.dumps(session_transcript)
        session_transcript_cbor_b64 = base64.b64encode(session_transcript_cbor).decode("utf-8")

        zk_verification_payload = {
            "ZKDeviceResponseCBOR": device_response_b64,
            "Transcript": session_transcript_cbor_b64
        }
        
        # 6. Send data to the ZK verification server and process the response
        try:
            print(f"Sending request to ZK Verifier at: {ZK_VERIFIER_URL}")
            headers = {
                "Content-Type": "application/json",
                # 'Authorization': f'Bearer {id_token}',
            }
            
            # NOTE: 'requests' library needs to be imported for this to work.
            response = requests.post(
                ZK_VERIFIER_URL,
                headers=headers,
                json=zk_verification_payload,
                timeout=80 # Add a timeout for robustness
            )
            
            # Raise an exception for bad status codes (4xx or 5xx)
            response.raise_for_status()
            
            # Parse the JSON response from the server
            verification_result = response.json()
            
            # Check the status provided by the verification logic
            if verification_result.get("Status") is True:
                print("ZK Verification Successful.")
                verified_claims = []
                # The claims are nested by namespace, e.g., "org.iso.18013.5.1"
                for namespace, claims_list in verification_result.get("Claims", {}).items():
                    for claim in claims_list:
                        verified_claims.append({
                            "name": claim.get("ElementIdentifier"),
                            "value": claim.get("ElementValue")
                        })
                return {"status": True, "verified_claims": verified_claims}
            else:
                # Verification failed, return the reason
                error_message = verification_result.get("Message", "Unknown verification failure.")
                print(f"ZK Verification Failed: {error_message}")
                return {"status": False, "message": error_message}

        except requests.exceptions.HTTPError as e:
            # Handle HTTP errors (e.g., 401 Unauthorized, 403 Forbidden, 500 Server Error)
            print(f"HTTP Error calling verification server: {e.response.status_code} {e.response.text}")
            return {"status": False, "message": f"Server error: {e.response.status_code}"}
        except requests.exceptions.RequestException as e:
            # Handle network errors (e.g., DNS failure, connection refused)
            print(f"Network error calling verification server: {e}")
            return {"status": False, "message": "Could not connect to verification server."}

    except jwe.InvalidJWEData as e:
        print(f"Error decrypting/processing JWE: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON payload inside JWE: {e}")
        return None
    except Exception as e:
        # Catch-all for other unexpected errors during processing
        print(f"An unexpected error occurred: {e}")
        return None


# --- Flask API Endpoints ---

@app.route('/request', methods=['POST'])
def handle_request_initiation():
    """
    API endpoint to generate a credential request payload and initial state.

    Expects JSON body:
    {
        "protocol": "openid4vp-v1-unsigned" | "openid4vp-v1-signed",
        "doctype": ["doctype_string_1", "doctype_string_2"], e.g., ["org.iso.18013.5.1.mDL"],
        "requestZkp" : True | False,
        "attributes": [ // Renamed from 'attrs' for clarity
            {"namespace": "namespace_string", "name": "attribute_name"},
            ...
        ]
    }

    Returns JSON response on success (200):
    {
        "protocol": "used_protocol",
        "request": { ... request payload specific to protocol ... }, // JSON object
        "state": { ... state data needed for verification (keys, nonce) ... }
    }
    or error JSON on failure (400 or 500).
    """
    try:
        request_data = request.get_json()
        if not request_data:
            return jsonify({'success': False, 'error': 'Invalid or empty JSON payload'}), 400

        # Extract data from the request
        protocol = request_data.get("protocol")
        doctypes = request_data.get("doctype") # Expect a list of strings
        # Use 'attributes' for consistency, default to empty list if missing
        requested_attributes = request_data.get("attributes", [])
        
        is_zkp_request = False
        if "requestZkp" in request_data and request_data["requestZkp"] == "True":
            is_zkp_request = True

        # --- Input Validation ---
        if not protocol or not doctypes:
            return jsonify({'success': False, 'error': 'Missing required fields: protocol, doctype'}), 400
        if not isinstance(doctypes, list) or not doctypes:
             return jsonify({'success': False, 'error': 'Field "doctype" must be a non-empty list.'}), 400
        # Check if the requested protocol is supported.
        if protocol not in openid4vp_protocols:
            return jsonify({'success': False, 'error': f'Unsupported protocol: {protocol}. Use one of {openid4vp_protocols}.'}), 400
        if not isinstance(requested_attributes, list):
             return jsonify({'success': False, 'error': 'Field "attributes" must be a list.'}), 400
        # --- End Validation ---

        # Generate common state (nonce)
        state = generate_request_state()
        nonce_base64 = state["nonce_base64"] # Nonce *without* padding

        generated_request_payload = None # Initialize

        if protocol in openid4vp_protocols:
            # Determine if the request is signed.
            is_signed_request = protocol == "openid4vp-v1-signed"

            # Generate an additional key pair specifically for JWE response encryption
            jwe_encryption_key_pair = jwk.JWK.generate(kty='EC', crv='P-256', use='enc', kid='1',alg=JWE_ALG)
            # Store the *private* key JSON representation in the state
            state['jwe_private_key_jwk'] = jwe_encryption_key_pair.export_private()
            # The public key goes into the request payload
            generated_request_payload = construct_openid4vp_request(
                doctypes, 
                requested_attributes, 
                nonce_base64, 
                jwe_encryption_key_pair, # Pass public JWK
                is_zkp_request,
                is_signed_request
            )

        # Ensure payload generation was successful (should be if inputs are valid)
        if generated_request_payload:
            response = {
                "protocol": protocol,
                # Return the dictionary directly; Flask's jsonify handles conversion
                "request": generated_request_payload,
                "state": state # Includes nonce and JWE private key
            }
            return jsonify(response), 200
        else:
            # This case implies an internal logic error if input validation passed
            print(f"Error: Failed to generate request payload for protocol {protocol}")
            return jsonify({'success': False, 'error': 'Internal server error: Failed to generate request payload'}), 500

    except Exception as e:
        print(f"Error during request generation endpoint: {e}") # Log the full error server-side
        # import traceback; traceback.print_exc() # Uncomment for detailed debugging
        return jsonify({'success': False, 'error': 'An unexpected error occurred during request generation.'}), 500

@app.route('/zkverify',methods=['POST'])
def handle_zk_verification():
    """
    API endpoint to process a Zero-Knowledge Proof (ZKP) credential response.
    It receives the encrypted data, decrypts it, and forwards it to an
    external ZK verification service.

    Expects JSON body:
    {
        "protocol": "openid4vp-v1-unsigned" | "openid4vp-v1-signed",
        "data": "encrypted_jwe_string",
        "state": { ... state from /request ... },
        "origin": "origin_string"
    }

    Returns JSON response:
    - On success (200): {"success": True, "credential_data": [ ... verified claims ... ]}
    - On failure (400/500): {"success": False, "error": "error_message"}
    """
    try:
        request_data = request.get_json()
        
        if not request_data:
            return jsonify({'success': False, 'error': 'Invalid or empty JSON payload'}), 400
        
        # --- Input Extraction and Validation ---
        protocol = request_data.get("protocol")
        state = request_data.get("state")
        origin=""
        if "origin" in request_data:
            origin = request_data.get("origin") # Get origin (required for openid4vp)
            # The actual encrypted data is nested under 'data' key for this endpoint
            request_data = request_data.get("data")
            
        if not protocol or state is None: # Check for required fields
            return jsonify({'success': False, 'error': 'Missing required fields: protocol, state'}), 400
        if protocol not in openid4vp_protocols:
             return jsonify({'success': False, 'error': f'Unsupported protocol: {protocol}. Use one of {openid4vp_protocols}.'}), 400
        if not isinstance(state, dict):
             return jsonify({'success': False, 'error': 'Invalid state object: must be a dictionary.'}), 400
        # --- End Validation ---        
        
        extracted_data = None # Initialize result
        # Determine if the request is signed.
        is_signed_request = protocol == "openid4vp-v1-signed"
        
        response_data = request_data.get("response")
        if not isinstance(response_data, str):
                return jsonify({'success': False, 'error': 'Invalid "data" format for openid4vp: expected a encrypted string'}), 400
        
        extracted_data = process_openid4vp_zk_response(response_data, state, origin, is_signed_request)

        if extracted_data is not None and extracted_data["status"]: # Success: could be an empty list [] or list with data
            return jsonify({'success': True, 'credential_data': extracted_data["verified_claims"]}), 200
        elif extracted_data is not None:
            return jsonify({'success': False, 'error': extracted_data["message"]}), 400
        else:
            # Internal processing error before contacting ZK verifier
            return jsonify({'success': False, 'error': 'Token processing or verification failed. Check server logs for details. '}), 400

    except Exception as e:
        print(f"Error during verification handling endpoint: {e}") # Log the full error server-side
        # import traceback; traceback.print_exc() # Uncomment for detailed debugging
        return jsonify({'success': False, 'error': 'An unexpected error occurred during verification.'}), 500


@app.route('/verify', methods=['POST'])
def handle_verification():
    """
    API endpoint to receive and verify the credential response from the wallet.

    Expects JSON body:
    {
        "protocol": "openid4vp-v1-unsigned" | "openid4vp-v1-signed",
        "data": { ... } or "base64_string", // The response data from wallet
                 // For openid4vp ('direct_post.jwt'), often: {"response": "jwe_string"}
        "state": { ... state data returned by /request endpoint ... },
        "origin": "origin_string" // Required for openid4vp (e.g., "https://...", "android:apk...")
    }

    Returns JSON response on success (200):
    {
        "success": True,
        "credential_data": [ {"name": ..., "value": ...}, ... ] // List can be empty if no attributes disclosed
    }
    or error JSON on failure (400 or 500):
    {
        "success": False,
        "error": "error_message"
    }
    """
    try:
        request_data = request.get_json()
        if not request_data:
            return jsonify({'success': False, 'error': 'Invalid or empty JSON payload'}), 400
        # Extract required fields
        protocol = request_data.get("protocol")
        state = request_data.get("state")
        origin=""
        # 'origin' and 'data' are at different levels depending on frontend structure, handle both
        if "origin" in request_data:
            origin = request_data.get("origin") # Get origin (required for openid4vp)
            request_data = request_data.get("data")
            
        # --- Input Validation ---
        if not protocol or state is None: # Check response_data existence
            return jsonify({'success': False, 'error': 'Missing required fields: protocol, state'}), 400
        # Check if the requested protocol is supported.
        if protocol not in openid4vp_protocols:
             return jsonify({'success': False, 'error': f'Unsupported protocol: {protocol}. Use one of {openid4vp_protocols}.'}), 400
        if protocol in openid4vp_protocols and (not origin or "response" not in request_data):
             # Origin is crucial for constructing the correct SessionTranscript in OpenID4VP
             return jsonify({'success': False, 'error': f'Missing required field for {protocol}: origin and data.response'}), 400
        if not isinstance(state, dict):
             return jsonify({'success': False, 'error': 'Invalid state object: must be a dictionary.'}), 400
        # --- End Validation ---

        extracted_data = None # Initialize result

        # --- Process based on protocol ---
        if protocol in openid4vp_protocols:
            # Determine if the request is signed.
            is_signed_request = protocol == "openid4vp-v1-signed"
            # Expect data to be a dictionary like {"response": "jwe_string"} for dc_api.jwt
            response_data = request_data.get("response")
            if not isinstance(response_data, str):
                 return jsonify({'success': False, 'error': 'Invalid "data" format for openid4vp: expected a encrypted string'}), 400
            extracted_data = process_openid4vp_response(response_data, state, origin, is_signed_request)

        # --- End Processing ---

        # Check the result from the processing functions
        if extracted_data is not None: # Success: could be an empty list [] or list with data
            return jsonify({'success': True, 'credential_data': extracted_data}), 200
        else:
            # Errors are printed/logged within the processing functions
            # Return a generic failure message to the client
            return jsonify({'success': False, 'error': 'Token processing or verification failed. Check server logs for details.'}), 400

    except Exception as e:
        print(f"Error during verification handling endpoint: {e}") # Log the full error server-side
        # import traceback; traceback.print_exc() # Uncomment for detailed debugging
        return jsonify({'success': False, 'error': 'An unexpected error occurred during verification.'}), 500


@app.route('/', methods=['GET'])
def home():
    """Renders the main HTML page for the Relying Party (RP) web application."""
    return render_template("RP_web.html")

@app.route('/request', methods=['GET'])
@app.route('/verify', methods=['GET'])
def handle_get_requests():
    """
    Handles GET requests to endpoints that only support POST.
    Returns a 405 Method Not Allowed error.
    """
    return jsonify({'error': 'Method Not Allowed. Please use POST.'}), 405

# --- Main Execution ---
if __name__ == '__main__':
    # Run Flask's development server
    # - debug=True enables auto-reloading and detailed error pages (DO NOT USE IN PRODUCTION)
    # - host='0.0.0.0' makes the server accessible from other devices on the network
    # - port=5001 changes the default port from 5000
    # For production, use a proper WSGI server like Gunicorn or uWSGI behind a reverse proxy (Nginx, Apache).
    print("Starting Flask development server...")
    print("WARNING: Debug mode is ON. Do not use in production.")
    print("WARNING: developement code only, Don't use state array(list) in production")
    app.run(debug=True, host='0.0.0.0', port=5001)