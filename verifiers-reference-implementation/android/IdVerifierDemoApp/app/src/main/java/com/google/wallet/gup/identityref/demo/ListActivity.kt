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

import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.lifecycle.lifecycleScope
import org.json.JSONArray
import org.json.JSONObject

/**
 * Main Activity class for the IdentityRef Demo App.
 * This activity handles user input, initiates the credential verification flow,
 * and displays the verification results.
 */
@OptIn(ExperimentalDigitalCredentialApi::class)
class ListActivity : AppCompatActivity() {

    private lateinit var editTextFirstName: EditText
    private lateinit var editTextLastName: EditText
    private lateinit var editTextAddress: EditText
    private lateinit var editTextState: EditText
    private lateinit var editTextPin: EditText
    private lateinit var editTextAge: EditText
    private lateinit var buttonVerifyDigitalId: Button

    private lateinit var serverRequestHandler: ServerRequestHandler
    private lateinit var walletCredentialHandler: WalletCredentialHandler

    private var selectedDoctypes: List<String> = emptyList()
    private var selectedAttributes: List<Attribute> = emptyList()
    private var requestZk: Boolean = false
    private var selectedProtocol: String = ""

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_list)

        // Initialize UI elements
        initializeViews()

        // Get data from Intent
        getIntentData()

        // Initialize handlers
        serverRequestHandler = ServerRequestHandler(this, lifecycleScope)
        walletCredentialHandler = WalletCredentialHandler(this@ListActivity, lifecycleScope)


        buttonVerifyDigitalId.setOnClickListener {
            if (isRequestValid()) {
                val createCredentialRequestJson = createRequestJsonData(
                    protocol = selectedProtocol,
                    doctypes = selectedDoctypes,
                    attributes = selectedAttributes,
                    requestZkp = requestZk
                )
                // Request credential details from server
                serverRequestHandler.requestCredentialFromServer(
                    getString(R.string.server_request_url),
                    createCredentialRequestJson,
                    ::handleServerRequestSuccess,
                    ::handleRequestFailure
                )
            }
        }
    }

    private fun initializeViews() {
        editTextFirstName = findViewById(R.id.firstNameEditText)
        editTextLastName = findViewById(R.id.lastNameEditText)
        editTextAddress = findViewById(R.id.addressEditText)
        editTextState = findViewById(R.id.stateEditText)
        editTextPin = findViewById(R.id.pinCodeEditText)
        editTextAge = findViewById(R.id.ageEditText)
        buttonVerifyDigitalId = findViewById(R.id.digitalIdButton)
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun getIntentData() {
        selectedDoctypes = intent.getStringArrayListExtra(Constants.EXTRA_SELECTED_DOCTYPES) ?: emptyList()
        selectedAttributes = intent.getParcelableArrayListExtra(Constants.EXTRA_SELECTED_ATTRIBUTES, Attribute::class.java) ?: emptyList()
        requestZk = intent.getBooleanExtra(Constants.EXTRA_REQUEST_ZK, false)
        selectedProtocol = intent.getStringExtra(Constants.EXTRA_SELECTED_PROTOCOL) ?: getString(R.string.protocol_openid4vp)
    }

    private fun isRequestValid(): Boolean {
        if (selectedDoctypes.isEmpty()) {
            Toast.makeText(this, R.string.no_doc_type_selected, Toast.LENGTH_LONG).show()
            return false
        }
        if (selectedAttributes.isEmpty()) {
            Toast.makeText(this, R.string.no_attributes_selected, Toast.LENGTH_LONG).show()
            return false
        }
        return true
    }

    private fun handleServerRequestSuccess(requestCredentialApiResponseJSON: JSONObject) {
        val requestJson = JSONObject().apply {
            put(Constants.KEY_REQUESTS, JSONArray().apply {
                put(JSONObject().apply {
                    put(Constants.KEY_PROTOCOL, requestCredentialApiResponseJSON.getString(Constants.KEY_PROTOCOL))
                    put(Constants.KEY_DATA, requestCredentialApiResponseJSON.getString("request"))
                })
            })
        }
        // Get credential details from wallet using the server response and state
        walletCredentialHandler.getCredentialDetailsFromWallet(
            requestJson.toString(),
            requestCredentialApiResponseJSON.getJSONObject(Constants.KEY_STATE),
            ::handleWalletResponseSuccess,
            ::handleWalletResponseFailure
        )
    }

    /**
     * Handles the successful response from the wallet.
     * Sends the wallet response back to the server for validation.
     *
     * @param responseJson The JSON response from the wallet containing the credential.
     * @param state The state object received from the initial server request.
     */
    private fun handleWalletResponseSuccess(responseJson: JSONObject, state: JSONObject) {
        responseJson.put(Constants.KEY_STATE, state)
            responseJson.put(Constants.KEY_ORIGIN, applicationContext.packageName)

        serverRequestHandler.sendWalletResponseToServer(
            getString(R.string.server_verify_url),
            responseJson,
            ::handleValidationSuccess,
            ::handleValidationFailure
        )
    }

    private fun handleValidationSuccess(response: JSONObject) {
        if (response.optBoolean(Constants.KEY_SUCCESS)) {
            val credentialData = response.optJSONArray(Constants.KEY_CREDENTIAL_DATA) ?: return
            val receivedAttributes = mutableMapOf<String, String>()

            for (i in 0 until credentialData.length()) {
                val item = credentialData.getJSONObject(i)
                val value = item.optString(Constants.KEY_VALUE, item.optBoolean(Constants.KEY_VALUE).toString())
                receivedAttributes[item.getString(Constants.KEY_NAME)] = value
            }

            runOnUiThread {
                updateUiWithValidatedData(receivedAttributes)
            }
        } else {
            handleValidationFailure(response.optString(Constants.KEY_ERROR, "Unknown validation error"))
        }
    }

    private fun updateUiWithValidatedData(attributes: Map<String, String>) {
        attributes[Constants.KEY_GIVEN_NAME]?.let { editTextFirstName.setText(it) }
        attributes[Constants.KEY_FAMILY_NAME]?.let { editTextLastName.setText(it) }
        attributes[Constants.KEY_RESIDENT_ADDRESS]?.let { editTextAddress.setText(it) }
        attributes[Constants.KEY_RESIDENT_STATE]?.let { editTextState.setText(it) }
        attributes[Constants.KEY_RESIDENT_POSTAL_CODE]?.let { editTextPin.setText(it) }

        // Handle various age-related attributes
        val ageOver18 = attributes[Constants.KEY_AGE_OVER_18]
        val ageOver21 = attributes[Constants.KEY_AGE_OVER_21]

        when {
            ageOver18 != null -> editTextAge.setText(if (ageOver18.toBoolean()) getString(R.string.age_over_18_yes) else getString(R.string.age_over_18_no))
            ageOver21 != null -> editTextAge.setText(if (ageOver21.toBoolean()) getString(R.string.age_over_21_yes) else getString(R.string.age_over_21_no))
            attributes[Constants.KEY_AGE_IN_YEARS] != null -> editTextAge.setText(attributes[Constants.KEY_AGE_IN_YEARS])
        }
    }

    private fun handleRequestFailure(errorMessage: String) {
        Toast.makeText(this@ListActivity, "Request Failed: $errorMessage", Toast.LENGTH_LONG).show()
    }

    private fun handleWalletResponseFailure(errorMessage: String) {
        Toast.makeText(this@ListActivity, "Wallet Error: $errorMessage", Toast.LENGTH_LONG).show()
    }

    private fun handleValidationFailure(errorMessage: String) {
        Toast.makeText(this@ListActivity, "Validation Failed: $errorMessage", Toast.LENGTH_LONG).show()
    }


    /**
     * Creates a JSON object representing the credential request data.
     * This data is sent to the server to initiate the credential request flow.
     *
     * @return JSONObject The JSON object containing the credential request data.
     */
    private fun createRequestJsonData(protocol: String, doctypes: List<String>, attributes: List<Attribute>, requestZkp: Boolean): JSONObject {
        return JSONObject().apply {
            put(Constants.KEY_PROTOCOL, protocol)
            put(Constants.KEY_DOCTYPE, JSONArray(doctypes))
            put(Constants.EXTRA_REQUEST_ZK, requestZkp)
            put(Constants.KEY_ATTRIBUTES, JSONArray().apply {
                attributes.forEach { attribute ->
                    put(JSONObject().apply {
                        put(Constants.KEY_NAMESPACE, attribute.namespace)
                        put(Constants.KEY_NAME, attribute.id)
                    })
                }
            })
        }
    }
}