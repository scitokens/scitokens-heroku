from flask import Flask, jsonify, request, send_from_directory
import json
from datetime import datetime
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

@app.route('/')
def homepage():
    return send_from_directory("./", 'index.html')

# Oauth well known    
@app.route('/.well-known/openid-configuration')
def OpenIDConfiguration():
    # We need more to be compliant with the RFC
    configuration = {
        "issuer": "https://demo.scitokens.org",
        "jwks_uri": "https://demo.scitokens.org/oauth2/certs"
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
            payload = json.loads(dataDict['payload'])
            algorithm = dataDict['algorithm']
        except json.decoder.JSONDecodeError as json_err:
            return "", 400

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
    lifetime = 600
    if 'exp' in token:
        lifetime = token['exp'] - int(time.time())

    serialized_token = token.serialize(issuer = "https://demo.scitokens.org", lifetime = lifetime)
    return serialized_token

@app.route('/protected', methods=['GET'])
@scitokens_protect.protect(audience="https://demo.scitokens.org", scope="read:/protected")
def Protected():
    return "Protected resource"
    

if __name__ == '__main__':
    # Given the private key in the ENV PRIVATE_KEY, calculate the public key
    app.run(debug=True, use_reloader=True)
