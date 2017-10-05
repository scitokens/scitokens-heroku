

import scitokens
from functools import wraps
from flask import request
import traceback
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import os


def protect(**outer_kwargs):
    def real_decorator(some_function):
        
        @wraps(some_function)
        def wrapper(*args, **kwargs):
            
            if 'Authorization' not in request.headers:
                headers = {
                    'WWW-Authenticate': 'Bearer'
                }
                return ("No Authentication Header", 401, headers)
            
            bearer = request.headers.get("Authorization")
            if len(bearer.split()) != 2:
                headers = {
                    'WWW-Authenticate': 'Bearer'
                }
                return ("Authentication header incorrect format", 401, headers)
            
            serialized_token = bearer.split()[1]
            try:
                # Read in the private key environment variable
                private_key = serialization.load_pem_private_key(
                    base64.b64decode(os.environ['PRIVATE_KEY']),
                    password=None,
                    backend=default_backend()
                )
                
                # Get the public numbers
                public_key = private_key.public_key()
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                token = scitokens.SciToken.deserialize(serialized_token, audience = outer_kwargs['audience'], public_key = public_pem)
            except Exception as e:
                print(str(e))
                traceback.print_exc()
                headers = {
                    'WWW-Authenticate': 'Bearer'
                }
                return ("Unable to deserialize: %{}".format(str(e)), 401, headers)
            
            def check_scope(value):
                if value == outer_kwargs['scope']:
                    return True
                else:
                    return False
            def check_iss(value):
                if value == "https://demo.scitokens.org":
                    return True
                else:
                    return False
            def return_true(value):
                return True
            
            validator = scitokens.Validator()
            validator.add_validator('scope', check_scope)
            validator.add_validator('iss', check_iss)
            validator.add_validator('iat', return_true)
            validator.add_validator('exp', return_true)
            validator.add_validator('nbf', return_true)
            validator.add_validator('aud', return_true)
            
            try:
                validator.validate(token)
            except scitokens.scitokens.ClaimInvalid as ce:
                headers = {
                    'WWW-Authenticate': 'Bearer'
                }
                return ("Validation incorrect", 403, headers)
            
            return some_function(*args, **kwargs)
    
        return wrapper
    return real_decorator
    
    

@protect(aud="asdf")
def stuff(blah, stuff, **kwargs):
    print(blah)
    print(stuff)
    for key, value in kwargs.iteritems():
        print("%s = %s" % (key, value))
    



