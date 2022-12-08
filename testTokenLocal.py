from flask import Flask, jsonify, request, send_from_directory, redirect, url_for
import json
from datetime import datetime, timedelta

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
import logging

import threading
import webbrowser
from wsgiref.simple_server import make_server


#https://stackoverflow.com/questions/336866/how-to-implement-a-minimal-server-for-ajax-in-python

PORT = 3333


@app.route('/localIssue', methods=['GET', 'POST'])
def localIssue():
    print("Post request received")
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
    
    return "HELLO"
    
    
def start_server():
    """Start the server."""
    httpd = make_server("", PORT, localIssue)
    httpd.serve_forever()

start_server()