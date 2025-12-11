/* Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

package com.google.wallet.gup.identityref.demo

import android.content.Context
import android.util.Log
import android.widget.Toast
import androidx.credentials.CredentialManager
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialInterruptedException
import androidx.credentials.exceptions.NoCredentialException
import androidx.lifecycle.LifecycleCoroutineScope
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Handles interactions with the Android Credential Manager to get digital credentials from the wallet.
 *
 * @property context The application context.
 * @property lifecycleScope The lifecycle scope for coroutine management.
 */
@OptIn(ExperimentalDigitalCredentialApi::class)
class WalletCredentialHandler(private val context: Context, private val lifecycleScope: LifecycleCoroutineScope) {


    /**
     * Retrieves credential details from the user's wallet using the Android Credential Manager.
     *
     * @param requestJson The JSON string representing the credential request.
     * @param state The state object associated with the request (can be JSONObject.NULL if not needed).
     * @param onSuccess Callback function to execute on successful retrieval of credentials, passing the response JSON and state.
     * @param onFailure Callback function to execute on failed retrieval of credentials, passing the error message.
     */
    fun getCredentialDetailsFromWallet(
        requestJson: String,
        state: JSONObject,
        onSuccess: (JSONObject, JSONObject) -> Unit,
        onFailure: (String) -> Unit
    ) {
        try {
            val credentialManager = CredentialManager.create(context)
            val digitalCredentialOption = GetDigitalCredentialOption(requestJson)
            val getCredRequest = GetCredentialRequest(listOf(digitalCredentialOption))


            // Handle the successfully returned credential.
            fun verifyResult(result: GetCredentialResponse) {
                when (val credential = result.credential) {
                    is DigitalCredential -> {
                        val responseJson = JSONObject(credential.credentialJson)
                        onSuccess(responseJson, state) // Pass response JSON and state and protocol to onSuccess
                        Toast.makeText(context, R.string.request_successful, Toast.LENGTH_LONG).show()
                    }
                    else -> {
                        Log.e("Invalid", "Unexpected type of credential ${credential.type}")
                        onFailure(context.getString(R.string.unexpected_credential_type))
                    }
                }
            }

            // Handle failure.
            fun handleFailure(e: GetCredentialException) {
                when (e) {
                    is GetCredentialCancellationException -> {
                        Toast.makeText(context, R.string.user_cancelled_activity, Toast.LENGTH_SHORT).show()
                        onFailure(context.getString(R.string.user_cancelled_request))
                    }
                    is GetCredentialInterruptedException -> {
                        Toast.makeText(context, R.string.retry_prompt, Toast.LENGTH_SHORT).show()
                        onFailure(context.getString(R.string.request_interrupted))
                    }
                    is NoCredentialException -> {
                        Log.w("Error", e.toString())
                        Toast.makeText(context, context.getString(R.string.no_credential_on_device) + e, Toast.LENGTH_SHORT).show()
                        onFailure(context.getString(R.string.no_credential_available))
                    }
                    else -> {
                        Log.e("something", "Unexpected exception type ${e::class.java}")
                        onFailure(context.getString(R.string.unexpected_error, e.message))
                    }
                }
            }

            lifecycleScope.launch {
                try {
                    val result = credentialManager.getCredential(
                        context = context,
                        request = getCredRequest
                    )
                    verifyResult(result)
                } catch (e: GetCredentialException) {
                    handleFailure(e)
                }
            }

        } catch (e: Exception) {
            Log.e("getCredDetailsFromWallet", "Exception during wallet interaction: ${e.message}", e)
            Toast.makeText(
                context,
                context.getString(R.string.wallet_interaction_exception, e.message),
                Toast.LENGTH_LONG
            ).show()
            onFailure(context.getString(R.string.wallet_interaction_exception, e.message))
        }
    }
}