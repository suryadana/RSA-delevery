from flask import Flask, request, session, redirect, render_template

import os
import json
import tempfile

import pytest

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random

from base64 import b64encode as b64enc,b64decode as b64dec

from datetime import timedelta
from flask import make_response, request, current_app
from functools import update_wrapper

app = Flask(__name__)
app.debug = True
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

@pytest.fixture
def client():
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True
    client = app.test_client()

    yield client

    os.close(db_fd)
    os.unlink(app.config['DATABASE'])


def crossdomain(origin=None, methods=None, headers=None,
                max_age=21600, attach_to_all=True,
                automatic_options=True):
    if methods is not None:
        methods = ', '.join(sorted(x.upper() for x in methods))
    if headers is not None and not isinstance(headers, str):
        headers = ', '.join(x.upper() for x in headers)
    if not isinstance(origin, str):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        max_age = max_age.total_seconds()

    def get_methods():
        if methods is not None:
            return methods

        options_resp = current_app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        def wrapped_function(*args, **kwargs):
            if automatic_options and request.method == 'OPTIONS':
                resp = current_app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))
            if not attach_to_all and request.method != 'OPTIONS':
                return resp

            h = resp.headers

            h['Access-Control-Allow-Origin'] = origin
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)
    return decorator


def generator_rsa():
	random_generator = Random.new().read
	private_key = RSA.generate(1024, random_generator)
	public_key = private_key.publickey()
	return private_key, public_key

def chunk_data(data, k=32):
	result = []
	for i in range(0, len(data), k):
		result.append(data[i:i+k])
	return result

def custom_rsa_encrypt(public_key, data):
	public_key = PKCS1_v1_5.new(public_key)
	chunk_result = chunk_data(data)
	result = b""
	for dt in chunk_result:
		b_dt = str.encode(dt)
		result += b64enc(public_key.encrypt(b_dt)) + b"$"
	return result

def custom_rsa_decrypt(private_key, data):
	result = b""
	if type(data) == bytes:
		data = data.decode()
	datas = data.split("$")
	sentinel = Random.new().read(256)
	private_key = PKCS1_v1_5.new(private_key)
	for dt in datas:
		b_dt = str.encode(dt)
		b64_dt = b64dec(b_dt)
		if b64_dt != b"":
			result += private_key.decrypt(b64_dt, None)
	return result

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/private')
def private():
	return session['private_key']

@app.route('/public')
def public():
	return session['public_key']

@app.route('/audit', methods=('GET', 'POST'))
def audit():
	if request.method == 'GET':
		private_key, public_key = generator_rsa()
		session['private_key'] = private_key.exportKey().decode()
		session['public_key'] = public_key.exportKey().decode()
		return public_key.exportKey().decode()

	if request.method == 'POST':
		private_key = session.pop('private_key', None)
		if private_key:
			private_key = RSA.importKey(private_key)
			req = custom_rsa_decrypt(private_key, request.data)
			req_obj = json.loads(req)
			if req_obj.get('data', None):
				client_private_key = req_obj['private_key']
				client_public_key = req_obj['public_key']
				client_data = req_obj['data']

				client_priv = RSA.importKey(client_private_key)
				client_pub = RSA.importKey(client_public_key)

				data = custom_rsa_decrypt(client_priv, client_data)

				return custom_rsa_encrypt(client_pub, "Horas you win!.")
			return "Data not found."
		else:
			return redirect('/audit')