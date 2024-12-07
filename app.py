
# from flask import Flask, request, jsonify, redirect, url_for, session
# import re
# import os
# import base64
# from google_auth_oauthlib.flow import Flow
# from google.oauth2.credentials import Credentials
# from googleapiclient.discovery import build
# from deadline import start_fetching_deadline


# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allows HTTP for OAuth



# app = Flask(__name__)
# app.secret_key = 'your_secret_key'

# CLIENT_SECRETS_FILE = 'credentials.json'  # Path to your credentials.json

# # Update the scopes to include Gmail API, profile, and email information
# SCOPES = [
#     'https://www.googleapis.com/auth/gmail.readonly',
#     'https://www.googleapis.com/auth/userinfo.profile',
#     'https://www.googleapis.com/auth/userinfo.email',
#     'openid'
# ]

# @app.route('/')
# def index():
#     return 'Welcome to the Gmail API Demo. <a href="/login">Login with Google</a>'

# @app.route('/login')
# def login():
#     flow = Flow.from_client_secrets_file(
#         CLIENT_SECRETS_FILE,
#         scopes=SCOPES,
#         redirect_uri='http://localhost:8080/callback'  # Set your redirect URI
#     )
   
#     authorization_url, state = flow.authorization_url(access_type='offline')
#     session['state'] = state
#     return redirect(authorization_url)

# @app.route('/callback')  # Matches the redirect URI
# def oauth2callback():
#     flow = Flow.from_client_secrets_file(
#         CLIENT_SECRETS_FILE,
#         scopes=SCOPES,
#         redirect_uri='http://localhost:8080/callback'
#     )
#     flow.fetch_token(authorization_response=request.url)
#     credentials = flow.credentials
#     session['credentials'] = credentials_to_dict(credentials)
#     return redirect(url_for('read_emails'))

# @app.route('/read_emails')
# def read_emails():
#     credentials = session.get('credentials')
#     if not credentials:
#         return jsonify({'error': 'Token not found, please login again.'}), 401

#     credentials = Credentials(**credentials)
#     service = build('gmail', 'v1', credentials=credentials)

#     results = service.users().messages().list(userId='me', maxResults=8).execute()
#     messages = results.get('messages', [])
#     email_list = []
    
#     if messages:
#         for message in messages:
#             msg = service.users().messages().get(userId='me', id=message['id']).execute()
            
#             payload = msg['payload']
#             headers = payload.get('headers', [])
#             body = ""
#             if 'parts' in payload:  # Handle multipart messages
#                 for part in payload['parts']:
#                     if part['mimeType'] == 'text/plain':
#                         body = part['body']['data']
#                         break
#             else:
#                 body = payload['body']['data']
            
#             body = base64.urlsafe_b64decode(body).decode('utf-8')
#             body = re.sub(r'http\S+', '', body)  # remove URLs
#             subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')

#             email_list.append({
#                 'id': message['id'],
#                 'subject': subject,
#                 'body': body,
#                 'snippet': msg['snippet']
#             })
#             email_list[0] = {
#                 'id': message['id'],
#                 'subject': "hackothan that is beign conducted in kmit college",
#                 'body': "hello dear user, you are a registered contestant for the hackathon that is being conducted in kmit and to participate you must pay the registration fee by 3-11-2024",
#                 'snippet': msg['snippet']
#             }
    
    
#     # return jsonify(email_list)
#     return jsonify(start_fetching_deadline(email_list))



    
# @app.route('/user_info')
# def user_info():
#     """Fetch and display user's profile and email information."""
#     credentials = session.get('credentials')
#     if not credentials:
#         return jsonify({'error': 'Token not found, please login again.'}), 401

#     credentials = Credentials(**credentials)
#     service = build('oauth2', 'v2', credentials=credentials)

#     user_info = service.userinfo().get().execute()
#     return jsonify(user_info)

# def credentials_to_dict(credentials):
#     return {
#         'token': credentials.token,
#         'refresh_token': credentials.refresh_token,
#         'token_uri': credentials.token_uri,
#         'client_id': credentials.client_id,
#         'client_secret': credentials.client_secret,
#         'scopes': credentials.scopes
#     }

# if __name__ == '__main__':
#     app.run(debug=True, port=8080)  # Port should match redirect URI




from flask import Flask, request, jsonify, redirect, url_for, session, render_template
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from pymongo import MongoClient
from deadline import start_fetching_deadline
from models.user_schema import UserSchema  # Import schema for validation
from datetime import datetime, timezone
import os
import base64
import re
from pydantic import ValidationError

# Environment variable for insecure transport
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Flask app setup
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MongoDB setup
client = MongoClient(os.getenv("MONGODB_KEY"))  # Replace with your MongoDB connection string (MONGODB_KEY)
db = client.user_data  # MongoDB database
users_collection = db.users  # Collection for storing user information

# Path to your credentials.json and scopes
CLIENT_SECRETS_FILE = 'credentials2.json'
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'
]

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri='http://localhost:8080/callback'  # Set your redirect URI
    )
    authorization_url, state = flow.authorization_url(access_type='offline',include_granted_scopes='true')
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

    if not credentials.refresh_token:
        return jsonify({'error': 'Refresh token is missing. Please ensure the authorization includes offline access.'}), 500
    # Store user credentials and info in session
    session['credentials'] = credentials_to_dict(credentials)

    # Get user info and store in the database
    
    user_service = build('oauth2', 'v2', credentials=credentials)
    user_info = user_service.userinfo().get().execute()

    # print("Storing OAuth credentials:", credentials_dict)
    # Check if the user already exists in the database
    existing_user = users_collection.find_one({'email': user_info['email']})
    
    if not existing_user:
        # New user: Redirect to a form to collect phone number
        redirect(url_for('first_login', email=user_info['email']))

    # Create user schema object
    user_data = UserSchema(
        email=user_info['email'],
        oauth_credentials=credentials_to_dict(credentials),
        created_time=datetime.now(timezone.utc)

    )

    # Store or update the user in the collection
    users_collection.update_one(
        {'email': user_info['email']},
        {'$set': {
            'email': user_info['email'],
            'oauth_credentials': credentials_to_dict(credentials),
            'created_time': datetime.now(timezone.utc)

        }},
        upsert=True
    )
    

    return redirect(url_for('read_emails'))

@app.route('/first_login')
def first_login():
    """Render a page for new users to input their phone number."""
    email = request.args.get('email')
    if not email:
        return jsonify({'error': 'Email parameter is missing.'}), 400
    return render_template('first_login.html', email=email)

@app.route('/submit_phone', methods=['POST'])
def submit_phone():
    """Handle the phone number input from new users."""
    email = request.form.get('email')
    phone_number = request.form.get('phone_number')
    
    if not email or not phone_number:
        return jsonify({'error': 'Email and phone number are required.'}), 400

    # Update the user in the collection with the phone number and created_time
    users_collection.update_one(
        {'email': email},
        {'$set': {
            'phone_number': phone_number,
            'created_time': datetime.now(timezone.utc)

        }},
        upsert=True
    )

    return redirect(url_for('read_emails'))

@app.route('/read_emails')
def read_emails():
    credentials = session.get('credentials')
    if not credentials:
        return jsonify({'error': 'Token not found, please login again.'}), 401

    credentials = Credentials(**credentials)
    service = build('gmail', 'v1', credentials=credentials)

    results = service.users().messages().list(userId='me', maxResults=8).execute()
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
            body = re.sub(r'http\S+', '', body)  # Remove URLs
            subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')

            email_list.append({
                'id': message['id'],
                'subject': subject,
                'body': body,
                'snippet': msg['snippet']
            })
    return jsonify(start_fetching_deadline(email_list))

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


def get_credentials_from_db(email):
    user = users_collection.find_one({'email': email})
    if user and 'oauth_credentials' in user:
        return Credentials.from_authorized_user_info(user['oauth_credentials'])
    return None

# Function to list emails
def list_emails(credentials):
    try:
        service = build('gmail', 'v1', credentials=credentials)
        results = service.users().messages().list(userId='me').execute()
        messages = results.get('messages', [])
        if not messages:
            print("No new messages.")
        else:
            for message in messages[:10]:  # Get the first 10 emails
                msg = service.users().messages().get(userId='me', id=message['id']).execute()
                print("Email snippet:", msg['snippet'])
    except Exception as e:
        print("An error occurred:", e)

@app.route('/parse-emails/<email>')
def parse_emails(email):
    credentials = get_credentials_from_db(email)
    if credentials:
        list_emails(credentials)
        return "Emails parsed successfully. Check console for email snippets."
    else:
        return "No credentials found for this user. Please authorize the user first."
    
if __name__ == '__main__':
    # parse_users()
    app.run(debug=True, port=8080)  # Port should match redirect URI

