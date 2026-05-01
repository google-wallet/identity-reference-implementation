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

# --- Purpose of this file ---
# This file contains the private key and certificate used for SIGNING requests
# when using the 'openid4vp-v1-signed' protocol.
# They are NOT used for verifying the response.
#
# --- Production Security Warning ---
# DO NOT use these hardcoded self-signed keys in production!
# In production, you should:
# 1. Use a real certificate issued by a trusted authority.
# 2. Store the private key securely in a Key Management Service (KMS) or hardware security module (HSM).
# 3. Do not commit private keys to source control.

PRIVATE_KEY = """-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAc1jY4u2abdGT73xOAFbos47jzbFgGqQBUXtQeOfxZroAoGCCqGSM49
AwEHoUQDQgAENZnak7+/ZBCEFbIh5/x0swiZuEEEoVVeykJ/SeV3z3Wiph/f8oMh
HBUAt6kS+k9SOwGfc7fKrEWJLgAeMxI97A==
-----END EC PRIVATE KEY-----"""

CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIBGDCBvgIJAOvRMvbc+21VMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCWxvY2Fs
aG9zdDAeFw0yNjA0MjgxNDA1MzZaFw0yNzA0MjgxNDA1MzZaMBQxEjAQBgNVBAMM
CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDWZ2pO/v2QQhBWy
Ief8dLMImbhBBKFVXspCf0nld891oqYf3/KDIRwVALepEvpPUjsBn3O3yqxFiS4A
HjMSPewwCgYIKoZIzj0EAwIDSQAwRgIhAIQv1PzR9RBfPL8YyQztI7C3uCinjKK6
LUTh/UVk5JETAiEAsg0rA+pMpm9HU4uZpR67lbVgHGbuo/rUKVpOKF7Dld4=
-----END CERTIFICATE-----"""
