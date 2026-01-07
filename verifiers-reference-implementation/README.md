# Identity relying party Reference repository


> This is not an officially supported Google product. This project is not
eligible for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security). This project is intended for demonstration purposes only. It is not
intended for use in a production environment.

This repository consists of Reference code for Identity relying parties to reference for their implementation for Google Wallet.

****
## Android Client Code

The Android code can be broken down into 3 parts:
* `ServerRequestHandler`
   - This is responsible for getting the credential request from the server and passing the credential response token back to the server.
* `WalletCredentialHandler`
   - This is responsible for getting the credential from a wallet on the device using the credential request from ServerRequest Handler.
* `ListActivity`
   - This file defined the [attributes](https://developers.google.com/wallet/identity/verify/supported-credential-attributes) that are required from the digital identity credential and triggers the process of requesting the credentials from wallet.

***

## Python Server Code

This is a Python-based web server built with **Flask** that acts as a Relying Party (RP). Its primary function is to request and verify digital credentials from a user's wallet. It supports the `openid4vp` protocol for this interaction. The server generates a request, sends it to a wallet, receives an encrypted response, and then decrypts and verifies the credential data.

The server provides a simple web interface to initiate the process and view the results and includes components for OpenID4VP.

> NOTE: Server code builds a state array (list) that contains JWE and HPKE keys. This is for illustration purposes only. For Production, use appropriate key management solutions to generate and store the keys, and only pass the public keys with nonce where needed in the request. State Array is not required.

### Relying Party (RP) Server for Credential Verification

***

### Prerequisites

Before you begin, ensure you have the following installed on your system:
* **Python 3.11** or later
* **pip** (Python package installer)
* **virtualenv** (recommended for isolating project dependencies)

***

### Setup Instructions

Follow these steps to get your server running locally.

#### 1. Clone the Repository
First, get a copy of the project on your local machine.
```bash
git clone <your-repository-url>
cd <repository-directory>
```

#### 2. Create and Activate a Virtual Environment
It's a best practice to create a virtual environment to manage the project's dependencies separately.

* **Create the environment:**
    ```bash
    python -m venv venv
    ```

* **Activate the environment:**
    * On **macOS and Linux**:
        ```bash
        source venv/bin/activate
        ```
    * On **Windows**:
        ```bash
        .\venv\Scripts\activate
        ```
    Your terminal prompt should now be prefixed with `(venv)`.

#### 3. Install Dependencies
Install all the required Python packages using the `requirements.txt` file.
```bash
pip install -r requirements.txt
```

***

### Configuration

Before running the server, you need to configure a few important variables in the `main.py` file. Open `main.py` and update the following placeholder values:

* **`APP_PACKAGE_NAME`**: Replace `"your.actual.app.package.name"` with your actual Android application's package name. This is crucial for the `openid4vp` protocol when interacting with an Android wallet.
    ```python
    # in main.py
    APP_PACKAGE_NAME = "your.actual.app.package.name"
    ```

* **`ANDROID_APP_SIGNATURE_HASH`**: Replace the placeholder hexadecimal string with the SHA-256 hash of your Android app's signing certificate. This is used to build the session transcript for verifying responses from an Android app.
    ```python
    # in main.py
    ANDROID_APP_SIGNATURE_HASH = "your_android_app_signature_hash_here"
    ```
* **`SPECS_URL`**: If you are using an external service for Zero-Knowledge Proof specifications, update this URL.
    ```python
    # in main.py
    SPECS_URL = "https://your-zk-specs-service.com/specs"
    ```

* **`ZK_VERIFIER_URL`**: If you are using an external Zero-Knowledge Proof verifier service, update this URL.
    ```python
    # in main.py
    ZK_VERIFIER_URL = "https://your-zk-verifier-service.com/zkverify"
    ```
***

### Running the Server

You can run the application using either the Flask development server or a production-ready WSGI server like Gunicorn.

#### Running in Development Mode
For local development and testing, you can use the built-in Flask server:
```bash
python main.py
```
By default, the server will be available at `http://0.0.0.0:5001`. You can access the web interface by navigating to this address in your web browser.

#### Running in Production Mode (with Gunicorn)
The `app.yaml` file is configured to use **Gunicorn**. You can also use it to run the server locally, which more closely simulates a production environment.
```bash
gunicorn -b :5001 main:app
```
This will start the server on port 5001.

***

## Deployment (Google App Engine)

This application is configured for easy deployment to **Google App Engine** using the `app.yaml` file.

1.  **Install the gcloud CLI**: Make sure you have the [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) installed and configured.
2.  **Deploy the app**: From the root directory of the project, run the following command:
    ```bash
    gcloud app deploy
    ```
The CLI will handle packaging your application, its dependencies, and deploying it based on the configuration in `app.yaml`.

***

### API Endpoints

The server exposes the following API endpoints:

* `GET /`
    * **Description**: Renders the main HTML web page (`RP_web.html`) for initiating credential requests on web.

* `POST /request`
    * **Description**: Initiates a request for a digital credential. It generates a state (including nonce and keys) and constructs a request payload for the specified protocol.
    * **Request Body** (JSON):
        ```json
        {
            "protocol": "openid4vp",
            "doctype": "string",
            "requestZkp": boolean,
            "attributes": [
                {"namespace": "string", "name": "string"}
            ]
        }
        ```
    * **Response** (JSON): The protocol, the generated request payload, and a state object to be used for verification.

* `POST /verify`
    * **Description**: Verifies the encrypted credential response from the wallet using the state generated by the `/request` endpoint.
    * **Request Body** (JSON):
        ```json
        {
            "protocol": "openid4vp",
            "data": "...",
            "state": { ... },
            "origin": "string"
        }
        ```
    * **Response** (JSON): A success or failure message, including the extracted credential data if verification is successful.

* `POST /zkverify`
    * **Description**: Verifies a Zero-Knowledge Proof response from the wallet by forwarding it to an external ZK verifier service.
    * **Request Body** (JSON): Similar to `/verify`.
    * **Response** (JSON): The verification result from the external service.
