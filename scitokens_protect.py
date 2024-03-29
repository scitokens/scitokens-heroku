

import scitokens
from functools import wraps
from flask import request
import traceback
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import os
import inspect


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
                token = scitokens.SciToken.deserialize(serialized_token, audience = outer_kwargs['audience'])
            except Exception as e:
                print(str(e))
                traceback.print_exc()
                headers = {
                    'WWW-Authenticate': 'Bearer'
                }
                return ("Unable to deserialize: %{}".format(str(e)), 401, headers)

            issuers = []
            if not isinstance(outer_kwargs['issuer'], list):
                issuers = [outer_kwargs['issuer']]
            else:
                issuers = outer_kwargs['issuer']
            success = False
            for issuer in issuers:
                enforcer = scitokens.Enforcer(issuer, audience=outer_kwargs['audience'])
                authz, path = outer_kwargs['scope'].split(":")

                if enforcer.test(token, authz, path):
                    success = True
                    break

            if not success:
                headers = {
                    'WWW-Authenticate': 'Bearer'
                }
                return ("Validation incorrect: {}".format(enforcer.last_failure), 403, headers)

            # If the function takes "token" as an argument, send the token
            if 'token' in inspect.getfullargspec(some_function).args:
                kwargs['token'] = token

            return some_function(*args, **kwargs)
    
        return wrapper
    return real_decorator
    
    

@protect(aud="asdf")
def stuff(blah, stuff, **kwargs):
    print(blah)
    print(stuff)
    for key, value in kwargs.iteritems():
        print("%s = %s" % (key, value))
    



