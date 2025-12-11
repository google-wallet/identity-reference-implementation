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
import androidx.lifecycle.LifecycleCoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

/**
 * Handles communication with the server for credential requests and validation.
 *
 * @property context The application context.
 * @property lifecycleScope The lifecycle scope for coroutine management.
 */
class ServerRequestHandler(private val context: Context, private val lifecycleScope: LifecycleCoroutineScope) {

    /**
     * Requests credential details from the server.
     * Sends a POST request to the specified server URL with the given JSON data.
     *
     * @param serverUrlString The URL of the server endpoint to request credentials from.
     * @param jsonData The JSON data to send in the request body.
     * @param onSuccess Callback function to execute on successful server response, passing the response JSON.
     * @param onFailure Callback function to execute on failed server response, passing the error message.
     */
    fun requestCredentialFromServer(
        serverUrlString: String,
        jsonData: JSONObject,
        onSuccess: (JSONObject) -> Unit,
        onFailure: (String) -> Unit
    ) {
        makePostRequest(serverUrlString, jsonData,
            successHandler = { connection ->
                val response = processSuccessfulResponse(connection)
                try {
                    onSuccess(JSONObject(response)) // Parse response as JSONObject and pass to onSuccess
                } catch (e: Exception) {
                    Log.e("ServerRequest", "Error parsing JSON response: ${e.message}")
                    onFailure(context.getString(R.string.parse_server_response_error))
                }
            },
            failureHandler = { connection ->
                val errorMessage = processFailedResponse(connection)
                onFailure(context.getString(R.string.request_to_server_failed, errorMessage)) // Pass error message to onFailure
            }
        )
    }

    /**
     * Sends the wallet response to the server for validation.
     * Sends a POST request to the specified server URL with the wallet response JSON data.
     *
     * @param serverUrlString The URL of the server endpoint for validation.
     * @param jsonData The JSON data containing the wallet response to send for validation.
     * @param onSuccess Callback function to execute on successful validation response, passing the response JSON array.
     * @param onFailure Callback function to execute on failed validation response, passing the error message.
     */
    fun sendWalletResponseToServer(
        serverUrlString: String,
        jsonData: JSONObject,
        onSuccess: (JSONObject) -> Unit,
        onFailure: (String) -> Unit
    ) {
        makePostRequest(serverUrlString, jsonData,
            successHandler = { connection ->
                val response = processSuccessfulResponse(connection)
                try {
                    onSuccess(JSONObject(response)) // Parse response as JSONObject and pass to onSuccess
                } catch (e: Exception) {
                    Log.e("ServerValidation", "Error parsing JSON response: ${e.message}")
                    onFailure(context.getString(R.string.parse_server_validation_error))
                }

            },
            failureHandler = { connection ->
                val errorMessage = processFailedResponse(connection)
                onFailure(context.getString(R.string.validation_request_failed, errorMessage)) // Pass error message to onFailure
            }
        )
    }


    /**
     * Makes a synchronous POST request to the server.
     * This is a private helper function to handle the network request logic.
     *
     * @param serverUrlString The URL for the POST request.
     * @param jsonData The JSON data to send in the request body.
     * @param successHandler Lambda to handle successful response (HTTP 200).
     * @param failureHandler Lambda to handle failed response (HTTP other than 200).
     */
    private fun makePostRequest(
        serverUrlString: String,
        jsonData: JSONObject,
        successHandler: (HttpURLConnection) -> Unit,
        failureHandler: (HttpURLConnection) -> Unit
    ) {
        lifecycleScope.launch(Dispatchers.IO) { // Launch coroutine for network operation
            try {
                val serverUrl = URL(serverUrlString)
                val connection = serverUrl.openConnection() as HttpURLConnection

                // Setup connection properties for POST request
                connection.requestMethod = "POST"
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.setRequestProperty("Accept", "application/json")

                // Write JSON data to output stream
                val outputStream = DataOutputStream(connection.outputStream)
                outputStream.write(jsonData.toString().toByteArray(StandardCharsets.UTF_8))
                outputStream.flush()
                outputStream.close()

                val responseCode = connection.responseCode
                if (responseCode == HttpURLConnection.HTTP_OK) {
                    successHandler(connection) // Handle successful response
                } else {
                    failureHandler(connection) // Handle failed response
                }
                connection.disconnect()

            } catch (e: Exception) {
                Log.e("SyncPostRequest", "Exception during request to $serverUrlString: ${e.message}", e)
                launch(Dispatchers.Main) { // Switch to main thread for UI operations
                    Toast.makeText(
                        context,
                        context.getString(R.string.request_exception, serverUrlString, e.message),
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }


    /**
     * Processes a successful HTTP response (200 OK).
     * Reads the response body and logs the success.
     *
     * @param connection The HttpURLConnection representing the successful connection.
     * @return The response body as a String.
     */
    private fun processSuccessfulResponse(connection: HttpURLConnection): String {
        val inputStream = BufferedReader(InputStreamReader(connection.inputStream))
        val response = inputStream.use { it.readText() } // Read entire response
        inputStream.close()
        Log.d("SyncPostRequest", "Success for URL: ${connection.url}")
        Log.d("SyncPostRequest", "Success Response Body: $response")
        return response
    }


    /**
     * Processes a failed HTTP response (non-200).
     * Reads the error stream and logs the error.
     *
     * @param connection The HttpURLConnection representing the failed connection.
     * @return The error response body as a String, or a default message if the body is empty.
     */
    private fun processFailedResponse(connection: HttpURLConnection): String {
        val errorStream = connection.errorStream
        val errorResponse = errorStream?.bufferedReader()?.use { it.readText() } ?: "No error response body"
        errorStream?.close()
        Log.e("SyncPostRequest", "Error for URL: ${connection.url}")
        Log.e("SyncPostRequest", "Error Response Body: $errorResponse")
        return errorResponse
    }
}