from flask import Flask, jsonify, request, send_from_directory, redirect, url_for
import json
from datetime import datetime

from scitokens.scitokens import SciToken
app = Flask(__name__, static_url_path='', static_folder='')
import os
import cryptography.utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import binascii
import scitokens
import scitokens_protect
import time
import requests
import redis
import uuid
import string
import random
r = redis.from_url(os.environ.get("REDIS_URL"))


def string_from_long(data):
    """
    Create a base64 encoded string for an integer
    """
    return base64.urlsafe_b64encode(cryptography.utils.int_to_bytes(data)).decode('ascii')

def bytes_from_long(data):
    """
    Create a base64 encoded bytes for an integer
    """
    return base64.urlsafe_b64encode(cryptography.utils.int_to_bytes(data))

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

@app.route('/')
def homepage():
    return send_from_directory("./", 'index.html')

@app.route('/device-code')
def deviceCode():
    return send_from_directory("./device-code/", 'index.html')

@app.route('/submit-code', methods=["POST"])
def submitCode():
    deviceCode = r.get(request.form["code"])
    r.set(deviceCode, "submitted", ex=3600)
    return redirect(url_for('homepage'))

@app.route("/oauth2/oidc-cm", methods=["POST"])
def clientRegister():
    """
    Register the client.  We don't really need to keep track of clients, so return
    the same data.
    """
    print(request.data)
    request_data = json.loads(request.data)
    return {
        "client_id": "test-client",
        "grant_types":["refresh_token","urn:ietf:params:oauth:grant-type:device_code"],
        "scope": request_data['scope']
    }

@app.route("/oauth2/device_authorization", methods=["POST"])
def deviceAuth():
    """
    Give the user a code and uuid for the device.  This is what the user actually returns.
    """
    print(request.data)
    print(request.form)
    userCode = id_generator()
    deviceCode = str(uuid.uuid4())
    r.set(userCode, deviceCode, ex=5*60)
    return {
        "user_code": userCode,
        "verification_url": "https://demo.scitokens.org/device-code",
        "device_code": deviceCode,
        "expires_in": 3600
    }

@app.route("/oauth2/token", methods=["POST"])
def issuerToken():
    """
    Check if the issuer has entered the code
    """
    print(request.form)
    deviceCode = request.form["device_code"]
    
    if r.get(deviceCode):
        # Generate the access code and refresh token
        accessToken = issueToken({
            "scope": "read:/protected",
        }, "ES256")
        refreshExpiration = int((datetime.datetime.now() + datetime.timedelta(days=31)).timestamp())
        refreshToken = issueToken({
            "scope": "read:/protected",
            "exp": refreshExpiration
        }, "ES256")
        return {
            "access_token": accessToken.decode('utf-8'),
            "expires_in": 20*60,
            "token_type": "Bearer",
            "refresh_token": refreshToken.decode('utf-8')
        }
    else:
        return {
            "error": "authorization_pending",
            "error_description": "Still waiting on user"
        }


# Oauth well known    
@app.route('/.well-known/openid-configuration')
def OpenIDConfiguration():
    # We need more to be compliant with the RFC
    configuration = {
        "issuer": "https://demo.scitokens.org",
        "jwks_uri": "https://demo.scitokens.org/oauth2/certs",
        "device_authorization_endpoint": "https://demo.scitokens.org/oauth2/device_authorization",
        "registration_endpoint": "https://demo.scitokens.org/oauth2/oidc-cm",
        "token_endpoint": "https://demo.scitokens.org/oauth2/token",
        "response_types_supported": [
            "code",
            "id_token"
        ],
        "response_modes_supported": [
            "query",
            "fragment",
            "form_post"
        ],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "subject_types_supported": [
            "public"
        ],
        "id_token_signing_alg_values_supported": [
            "RS256",
            "RS384",
            "RS512"
        ],
        "scopes_supported": [
            "read:/",
            "write:/"
        ],
        "claims_supported": [
            "aud",
            "exp",
            "iat",
            "iss",
            "sub"
        ]
    }
    return jsonify(configuration)
    

# jwks_uri 
@app.route('/oauth2/certs')
def Certs():
    """
    Provide the "keys"
    """
    
    if os.path.exists("private.pem"):
        private_key_str = open("private.pem").read()

    elif 'PRIVATE_KEY' in os.environ:
        private_key_str = base64.b64decode(os.environ['PRIVATE_KEY'])
    
    private_key = serialization.load_pem_private_key(
        private_key_str,
        password=None,
        backend=default_backend()
    )
    
    # Get the public numbers
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    
    # Hash the public "n", and use it for the Key ID (kid)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(bytes_from_long(numbers.n))
    kid = binascii.hexlify(digest.finalize())
    
    keys = {'keys': [
        {
            "alg": "RS256",
            "n": string_from_long(numbers.n),
            "e": string_from_long(numbers.e),
            "kty": "RSA",
            "use": "sig",
            "kid": "key-rs256"
        }
    ]}
    
    
    if os.path.exists("ec_private.pem"):
        private_key_str = open("ec_private.pem").read()

    elif 'EC_PRIVATE_KEY' in os.environ:
        private_key_str = base64.b64decode(os.environ['EC_PRIVATE_KEY'])

    private_key = serialization.load_pem_private_key(
        private_key_str,
        password=None,
        backend=default_backend()
    )
    
    # Get the public numbers
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    
    # Hash the public "n", and use it for the Key ID (kid)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(bytes_from_long(numbers.x))
    kid = binascii.hexlify(digest.finalize())
    
    keys['keys'].append({
        "alg": "ES256",
        "x": string_from_long(numbers.x),
        "y": string_from_long(numbers.y),
        "kty": "EC",
        "use": "sig",
        "kid": "key-es256"
    })
    
    
    return jsonify(keys)

@app.route('/issue', methods=['GET', 'POST'])
def Issue():
    """
    Issue a SciToken
    """

    algorithm = "RS256"
    payload = {}

    if request.method == 'POST':
        data = request.data
        try:
            dataDict = json.loads(data)
            payload = dataDict['payload']
            algorithm = dataDict['algorithm']
        except json.decoder.JSONDecodeError as json_err:
            return "", 400
    
    return issueToken(payload, algorithm)

def issueToken(payload, algorithm="RS256"):
    private_key_str = ""

    if algorithm == "RS256":

        # Load the private key
        if os.path.exists("private.pem"):
            private_key_str = open("private.pem").read()

        elif 'PRIVATE_KEY' in os.environ:
            private_key_str = base64.b64decode(os.environ['PRIVATE_KEY'])
        key_id = "key-rs256"
    elif algorithm == "ES256":
        # Load the private key
        if os.path.exists("ec_private.pem"):
            private_key_str = open("ec_private.pem").read()

        elif 'EC_PRIVATE_KEY' in os.environ:
            private_key_str = base64.b64decode(os.environ['EC_PRIVATE_KEY'])
        key_id = "key-es256"
    private_key = serialization.load_pem_private_key(
        private_key_str,
        password=None,
        backend=default_backend()
    )

    token = scitokens.SciToken(key = private_key, algorithm = algorithm, key_id=key_id)
    for key, value in payload.items():
        token.update_claims({key: value})

    if 'ver' not in token:
        token['ver'] = "scitoken:2.0"
    
    # If exp in the token submitted, then honor it by figuring out the lifetime
    # No less than 10 minute lifetimes
    lifetime = 600
    if 'exp' in token and (token['exp'] - time.time()) > 600:
        lifetime = token['exp'] - int(time.time())

    # Add aud if scitoken:2.0
    if 'ver' in token and token['ver'] == "scitoken:2.0" and 'aud' not in token:
        token['aud'] = "https://demo.scitokens.org"

    serialized_token = token.serialize(issuer = "https://demo.scitokens.org", lifetime = lifetime)
    return serialized_token

@app.route('/protected', methods=['GET'])
@scitokens_protect.protect(audience="https://demo.scitokens.org", scope="read:/protected", issuer=["https://demo.scitokens.org", "https://cilogon.org"])
def Protected():
    return "Succesfully accessed the protected resource!"


@app.route('/secret', methods=['GET'])
@scitokens_protect.protect(audience="https://demo.scitokens.org", scope="read:/secret", issuer="https://demo.scitokens.org")
def Secret(token: SciToken):
    """
    This is the first level of the secret
    """
    if 'sub' in token and "BADGR_TOKEN" in os.environ:
        email = token['sub']
        headers = {"Authorization": "Bearer " + os.environ["BADGR_TOKEN"] }
        badge = {
            "badgeclassOpenBadgeId": "https://api.badgr.io/public/badges/0xFqlz4bQ5qAd7FG6FIwEQ",
            "issuer": "oikqaDC8Sx2WPNXUYdh0Dw",
            "issuerOpenBadgeId": "https://api.badgr.io/public/issuers/oikqaDC8Sx2WPNXUYdh0Dw",
            "recipient": {
                "identity": email,
                "hashed": False,
                "type": "email",
                "salt": ""
            },
            "narrative": "Successfully queried the demo token issuer",
            "evidence": [
                {
                "url": "https://demo.scitokens.org",
                "narrative": "Successfully queried the demo token issuer"
                }
            ],
        }
        resp = requests.post("https://api.badgr.io/v2/issuers/oikqaDC8Sx2WPNXUYdh0Dw/assertions", json=badge, headers=headers)
        data = resp.json()
        returnedText = "Congratulations, you have earned the Demo Application badge: " + data["result"][0]['openBadgeId']
        return returnedText
    else:
        return "Congratulations!  But you didn't include an email in the 'sub' attribute of the token, therefore we cannot issue you a badge"
    


if __name__ == '__main__':
    # Given the private key in the ENV PRIVATE_KEY, calculate the public key
    app.run(debug=True, use_reloader=True)
