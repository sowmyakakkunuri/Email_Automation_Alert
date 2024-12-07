
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import re
import os
import base64
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
# from deadline import start_fetching_deadline
from responses import generate_email_reply, get_email_summary

from dotenv import load_dotenv
load_dotenv()



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


@app.route('/home')
def home():
    return render_template('index.html')

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

    # Use Gmail API to fetch user profile
    
    service = build('oauth2', 'v2', credentials=credentials)
    user_info = service.userinfo().get().execute()

    #  # Extract user details
    # user_email = user_info.get('email')
    # user_name = user_info.get('name', 'Unknown')
    # print(user_email, user_name)

    # existing_user = users_collection.find_one({"email": user_email})
    # print(existing_user)
    # if not existing_user:
    #     # Insert user into MongoDB
    #     users_collection.insert_one({
    #         "name": user_name,
    #         "email": user_email,
    #         "created_at": datetime.now()
    #     })

    # users_collection.insert_one({
    #     "name": "demo",
    #     "email": "demo",
    #     "created_at": datetime.now()
    # })    

        # acesss?????

    return redirect(url_for('home'))

    # return redirect(url_for('read_emails'))

@app.route('/user_options')
def user_options():
    return render_template('user_options.html')

@app.route('/fetch_emails', methods=['POST'])
def fetch_emails():
    user_input_num_of_emails = request.form.get('num_of_emails', default=8, type=int)
    print("the numvbeaghajcm: ",request.form.get('num_of_emails'))
    return redirect(url_for('read_emails', max_results=user_input_num_of_emails))

@app.route('/read_emails/<int:max_results>')
def read_emails(max_results=8):
    credentials = session.get('credentials')
    if not credentials:
        return jsonify({'error': 'Token not found, please login again.'}), 401

    credentials = Credentials(**credentials)
    service = build('gmail', 'v1', credentials=credentials)

    results = service.users().messages().list(userId='me', maxResults=max_results).execute()
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
            body = re.sub(r'http\S+', '', body)  # remove URLs
            subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')

            email_list.append({
                'id': message['id'],
                'subject': subject,
                'body': body,
                'snippet': msg['snippet']
            })

            # added a sample email
            # email_list[0] = {
            #     'id': message['id'],
            #     'subject': "hackothan that is beign conducted in kmit college",
            #     'body': "hello dear user, you are a registered contestant for the hackathon that is being conducted in kmit and to participate you must pay the registration fee by 3-11-2024",
            #     'snippet': "hackathon that is being conducted in kmit and to participate you must pay the registration fee by 3-11-2024"
            # }


        session['email_list'] = email_list    
        return render_template('emails.html', emails=email_list)
        # return jsonify(process_emails_with_llm(email_list))
    # return jsonify(email_list)
    # return jsonify(start_fetching_deadline(email_list))


@app.route('/auto_reply/<string:email_id>', methods=['POST'])
def auto_reply(email_id):
    email_list = session.get('email_list')
    email = next((email for email in email_list if email['id'] == email_id), None)
    if not email:
        return jsonify({'error': 'Email not found'}), 404
    

    smart_auto_reply = generate_email_reply(email)
    return render_template('email_content.html', email=email,reply=smart_auto_reply)


@app.route('/email_summarizer/<string:email_id>', methods=['POST'])
def email_summarizer(email_id):
   email_list = session.get('email_list')
   email = next((email for email in email_list if email['id'] == email_id), None)
   if not email:
        return jsonify({'error': 'Email not found'}), 404
   
   summary =  get_email_summary(email)
   return render_template('email_content.html', email=email, summary=summary)


@app.route('/email_content/<string:email_id>', methods=['GET'])
def email_content(email_id):
    email_list = session.get('email_list')
    
    email = next((email for email in email_list if email['id'] == email_id), None)
    if not email:
        return jsonify({'error': 'Email not found'}), 404

    return render_template('email_content.html', email=email)

    
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
