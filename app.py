
from flask import Flask, request, jsonify, redirect, url_for, session
import os
import base64
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allows HTTP for OAuth

app = Flask(__name__)
app.secret_key = 'your_secret_key'

CLIENT_SECRETS_FILE = 'credentials.json'  # Path to your credentials.json

# Update the scopes to include Gmail API, profile, and email information
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'
]

@app.route('/')
def index():
    return 'Welcome to the Gmail API Demo. <a href="/login">Login with Google</a>'

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri='http://localhost:8080/callback'  # Set your redirect URI
    )
    authorization_url, state = flow.authorization_url(access_type='offline')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')  # Matches the redirect URI
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri='http://localhost:8080/callback'
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    return redirect(url_for('read_emails'))

@app.route('/read_emails')
def read_emails():
    credentials = session.get('credentials')
    if not credentials:
        return jsonify({'error': 'Token not found, please login again.'}), 401

    credentials = Credentials(**credentials)
    service = build('gmail', 'v1', credentials=credentials)

    results = service.users().messages().list(userId='me', maxResults=20).execute()
    messages = results.get('messages', [])
    email_list = []
    
    if messages:
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            
            payload = msg['payload']
            headers = payload.get('headers', [])
            body = ""
            if 'parts' in payload:  # Handle multipart messages
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain':
                        body = part['body']['data']
                        break
            else:
                body = payload['body']['data']
            
            body = base64.urlsafe_b64decode(body).decode('utf-8')
            subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')

            email_list.append({
                'id': message['id'],
                'subject': subject,
                'body': body,
                'snippet': msg['snippet']
            })
    
    return jsonify(email_list)

@app.route('/user_info')
def user_info():
    """Fetch and display user's profile and email information."""
    credentials = session.get('credentials')
    if not credentials:
        return jsonify({'error': 'Token not found, please login again.'}), 401

    credentials = Credentials(**credentials)
    service = build('oauth2', 'v2', credentials=credentials)

    user_info = service.userinfo().get().execute()
    return jsonify(user_info)

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

if __name__ == '__main__':
    app.run(debug=True, port=8080)  # Port should match redirect URI