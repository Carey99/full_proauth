#!/usr/bin/python3
from flask import Flask, jsonify, send_from_directory, redirect, url_for, session, abort, render_template
from authlib.integrations.flask_client import OAuth
import random
import string
import threading
import time
import os
import requests

app = Flask(__name__, static_folder='stylesheets')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_secret_key')  # Default fallback

# OAuth configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='client_id',
    client_secret='client_secret',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'},
)

current_code = None

def generate_code():
    global current_code
    while True:
        current_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        time.sleep(60)

@app.route('/generate_code')
def get_code():
    return jsonify(code=current_code)

@app.route('/')
def index():
    if 'user' in session:
        user_name = session['user']['name']
        return render_template('index.html', user_name=user_name)
    return redirect(url_for('login_button'))

@app.route('/ProAuth')
def mainpage():
    if 'user' not in session:
        return redirect(url_for('login'))
    user_name = session['user']['name']
    return render_template('index.html', user_name=user_name)

@app.route('/stylesheets/<path:path>')
def send_css(path):
    return send_from_directory('stylesheets', path)

@app.route('/images/<path:path>')
def send_images(path):
    return send_from_directory('images', path)

@app.route('/videos/<path:path>')
def send_videos(path):
    return send_from_directory('videos', path)

@app.route('/login')
def login():
    nonce = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    session['nonce'] = nonce
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/callback')
def authorize():
    try:
        token = google.authorize_access_token()
        nonce = session.pop('nonce', None)
        if nonce is None:
            abort(400, description="Nonce not found in session.")
        user_info = google.parse_id_token(token, nonce=nonce)
        session['user'] = user_info
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error: {e}")
        abort(503, description="Service Unavailable")
    except Exception as e:
        print(f"Error during OAuth authorization: {e}")
        abort(500, description="Internal Server Error")
        return redirect(url_for('login_button'))
    return redirect(url_for('mainpage'))

@app.route('/protected')
def protected():
    if 'user' not in session:
        return redirect(url_for('login'))
    return f"Hello, {session['user']['name']}! Your generated code is {current_code}"

@app.route('/login_button')
def login_button():
    return render_template('login_button.html')

@app.route('/logout')
def logout():
    session.clear()  # Clear the entire session
    return redirect(url_for('login_button'))  # Redirect to the Google login

if __name__ == '__main__':
    code_thread = threading.Thread(target=generate_code)
    code_thread.daemon = True
    code_thread.start()
    app.run(debug=True)
