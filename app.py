from flask import Flask, jsonify
import json
from datetime import datetime
app = Flask(__name__)

@app.route('/')
def homepage():

    return """
    <h1>Hello from SciTokens!</h1>
    """.format()

# Oauth well known    
@app.route('/.well-known/openid-configuration')
def OpenIDConfiguration():
    configuration = {
        "issuer": "https://demo.scitokens.org",
        "jwks_uri": "https://demo.scitokens.org/oauth2/certs"
    }
    return jsonify(configuration)
    

# jwks_uri 
@app.route('/oauth2/certs')
def Certs():
    pass



if __name__ == '__main__':
    # Given the private key in the ENV PRIVATE_KEY, calculate the public key
    
    app.run(debug=True, use_reloader=True)
