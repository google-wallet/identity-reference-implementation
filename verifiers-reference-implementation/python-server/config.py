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

# --- Configuration ---

# TODO: Replace with your actual application's package name (for Android)
# Used in constructing the SessionTranscript for the 'preview' protocol.
APP_PACKAGE_NAME = "<your_app_package_name>"

# TODO: Replace with the actual SHA-256 hash of your Android app's signing certificate
# Used in constructing the SessionTranscript for the 'openid4vp' protocol when
# the origin is an Android app. Find using:
# keytool -printcert -jarfile your_app.apk | grep SHA256 | awk '{print $2}' | xxd -r -p | sha256sum | awk '{print $1}'
ANDROID_APP_SIGNATURE_HASH = "<your_app_signature_here_without_':'>"

# URL for the external Zero-Knowledge Verifier service's verification endpoint.
ZK_VERIFIER_URL = "<path_to_ZKverifier>/zkverify"
# URL for the external Zero-Knowledge Verifier service's specifications endpoint.
SPECS_URL = "<path_to_ZKverifier>/specs"

