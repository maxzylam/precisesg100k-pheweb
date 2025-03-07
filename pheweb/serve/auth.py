
from .. import conf

from flask import redirect, url_for, session, request, render_template
from rauth import OAuth2Service

import requests
import json

from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv

load_dotenv()

# It seems like everything is working without these two lines, and I'm not sure why: (maybe because I installed `requests[security]`?)
# import urllib3.contrib.pyopenssl
# urllib3.contrib.pyopenssl.inject_into_urllib3()

class GoogleSignIn(object):
    def __init__(self, current_app):
        google_params = self._get_google_info()
        self.service = OAuth2Service(
            name='google',
            client_id=conf.get_login_google_id_and_secret()[0],
            client_secret=conf.get_login_google_id_and_secret()[1],
            authorize_url=google_params.get('authorization_endpoint'),
            base_url=google_params.get('userinfo_endpoint'),
            access_token_url=google_params.get('token_endpoint')
        )

    def _get_google_info(self):
        # Previously I used: return json.loads(urllib2.urlopen('https://accounts.google.com/.well-known/openid-configuration'))
        r = requests.get('https://accounts.google.com/.well-known/openid-configuration')
        r.raise_for_status()
        return r.json()

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='email',
            response_type='code',
            prompt='select_account',
            redirect_uri=self.get_callback_url())
        )

    def get_callback_url(self):
        return url_for('.oauth_callback_google',
                       _external=True,
                       _scheme='https')  # Google only allows HTTPS callbacks, so assume https.  I don't know why flask didn't see X-SCHEME header or whatever.

    def callback(self):
        if 'code' not in request.args:
            return (None, None)
        # The following two commands pass **kwargs to requests.
        oauth_session = self.service.get_auth_session(
                data={'code': request.args['code'],
                      'grant_type': 'authorization_code',
                      'redirect_uri': self.get_callback_url()
                     },
                decoder = lambda x: json.loads(x.decode('utf-8'))
        )
        me = oauth_session.get('').json()
        return (me['name'] if 'name' in me else me['email'], # SAML emails (like @umich.edu) don't have 'name'
                me['email'])


class CognitoAuth:
    def __init__(self, current_app):
        self.app = current_app
        self.oauth = OAuth(current_app)
        self.oauth.register(
            name='oidc',
            authority=os.getenv('COGNITO_AUTHORITY'),
            client_id=os.getenv('COGNITO_CLIENT_ID'),
            client_secret=os.getenv('COGNITO_CLIENT_SECRET'),
            server_metadata_url=os.getenv('COGNITO_METADATA_URL'),
            client_kwargs={'scope': os.getenv('COGNITO_SCOPE', 'email openid phone')}
        )
    def login_page(self, error=None):
        """Render the login page"""
        return render_template('login.html', error=error)

    def authorize(self):
        redirect_uri = url_for('bp.oauth_callback_cognito', _external=True, _scheme='https')
        print(f"Redirected to {redirect_uri}")
        return self.oauth.oidc.authorize_redirect(redirect_uri)

    def callback(self):
        try:
            # Get the token
            token = self.oauth.oidc.authorize_access_token()
            
            # Get user info from the token
            userinfo = token.get('userinfo', {})
            email = userinfo.get('email', 'unknown@example.com')
            name = userinfo.get('name', 'User')
            
            # Set session variables to indicate successful login
            session['logged_in'] = True
            session['user_email'] = email
            session['user_name'] = name
            
            return (name, email)
            
        except Exception as e:
            print(f"Error in Cognito callback: {e}")
            return (None, None)