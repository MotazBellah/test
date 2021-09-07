import os
import time
from flask import Flask, jsonify, request, url_for, render_template, session, redirect
from models import db, User, Client, Token, AuthorizationCode
from authlib.integrations.flask_oauth2 import current_token
# from oauth2 import server
from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
    create_bearer_token_validator
)

from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)

from authlib.oidc.core.grants import (
    OpenIDCode as _OpenIDCode,
    OpenIDImplicitGrant as _OpenIDImplicitGrant,
    OpenIDHybridGrant as _OpenIDHybridGrant,
)
from authlib.oidc.core import UserInfo
from werkzeug.security import gen_salt
# from authlib.oidc.core import grants, UserInfo

from authlib.oauth2.rfc6749 import grants
from authlib.oauth2 import OAuth2Error


app = Flask(__name__)
app.secret_key = 'super secret key'


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['OAUTH2_REFRESH_TOKEN_GENERATOR'] = True

db.init_app(app)

require_oauth = ResourceProtector()

query_client = create_query_client_func(db.session, Client)
save_token = create_save_token_func(db.session, Token)

server = AuthorizationServer(
     query_client=query_client, save_token=save_token
)

JWT_CONFIG = {
    'key': 'secret-key',
    'alg': 'RS512',
    'iss': 'http://localhost:8000/',
    'exp': 3600,
}

class AuthorizationCodeGran(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']
    def save_authorization_code(self, code, request):
        client = request.client
        auth_code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def authenticate_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        if user.check_password(password):
            return user


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        # openid request MAY have "nonce" parameter
        nonce = request.data.get('nonce')
        auth_code = AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            nonce=nonce,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code


class OpenIDCode(_OpenIDCode):
    def exists_nonce(self, nonce, request):
        exists = AuthorizationCode.query.filter_by(
            client_id=request.client_id, nonce=nonce
        ).first()
        return bool(exists)

    def get_jwt_config(self, grant):
        return JWT_CONFIG

    def generate_user_info(self, user, scope):
        user_info = UserInfo(sub=user.id, name=user.name)
        # if 'email' in scope:
        #     user_info['email'] = user.email
        return user_info

class OpenIDImplicitGrant(_OpenIDImplicitGrant):
    def exists_nonce(self, nonce, request):
        exists = AuthorizationCode.query.filter_by(
            client_id=request.client_id, nonce=nonce
        ).first()
        return bool(exists)

    def get_jwt_config(self):
        return JWT_CONFIG

    def generate_user_info(self, user, scope):
        user_info = UserInfo(sub=user.id, name=user.name)
        if 'email' in scope:
            user_info['email'] = user.email
        return user_info

from authlib.common.security import generate_token

class OpenIDHybridGrant(_OpenIDHybridGrant):
    def save_authorization_code(self, code, request):
        nonce = request.data.get('nonce')
        item = AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            nonce=nonce,
        )
        db.session.add(item)
        db.session.commit()
        return code

    def exists_nonce(self, nonce, request):
        exists = AuthorizationCode.query.filter_by(
            client_id=request.client_id, nonce=nonce
        ).first()
        return bool(exists)

    def get_jwt_config(self):
        return JWT_CONFIG

    def generate_user_info(self, user, scope):
        user_info = UserInfo(sub=user.id, name=user.name)
        if 'email' in scope:
            user_info['email'] = user.email
        return user_info


def generate_user_info(user, scope):
    return UserInfo(sub=str(user.id), name=user.username)


def get_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)

    return None


@app.route('/', methods=['GET', 'POST'])
def home():
    print(server)
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        # if user is not just to log in, but need to head back to the auth page, then go for it
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect('/')
    user = get_user()
    if user:
        # Client.query.delete()
        # db.session.commit()
        # client_id = 'motaz12345'
        # client_id_issued_at = int(time.time())
        # client = Client(
        #     client_id=client_id,
        #     client_id_issued_at=client_id_issued_at,
        #     user_id=user.id,
        # )
        #
        #
        # client_metadata = {
        #     "client_name": 'me',
        #     "client_uri": 'http://localhost:4000/',
        #     "grant_types": ['authorization_code', 'password'],
        #     "redirect_uris": ['http://localhost:4000/', 'http://localhost:4000/authorize'],
        #     "response_types": ['code'],
        #     "scope": 'profile',
        #     "token_endpoint_auth_method": 'client_secret_basic'
        # }
        # client.set_client_metadata(client_metadata)
        #
        #
        # client.client_secret = 'ghobashi789'
        #
        # db.session.add(client)
        # db.session.commit()

        clients = Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []

    return render_template('home.html', user=user, clients=clients)

@app.route('/logout')
def logout():
    del session['id']
    return redirect('/')



@app.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    # Login is required since we need to know the current resource owner.
    # It can be done with a redirection to the login page, or a login
    # form on this authorization page.
    x = get_user()
    if not x:
        return redirect(url_for('home', next=request.url))
    if request.method == 'GET':
        x = get_user()
        print('###############')
        print(x)
        grant = server.validate_consent_request(end_user=x)
        print("?????????????????")
        print(grant)
        client = grant.client
        # scope = client.get_allowed_scope(grant.request.scope)
        # print(scope)

        # You may add a function to extract scope into a list of scopes
        # with rich information, e.g.
        # scopes = describe_scope(scope)  # returns [{'key': 'email', 'icon': '...'}]
        return render_template(
            'authorize.html',
            grant=grant,
            user=x,
            client=client,
            scopes='',
        )
    confirmed = request.form['confirm']
    if confirmed:
        # current_user = current_user()
        # granted by resource owner
        return server.create_authorization_response(grant_user=x)
    # denied by resource owner
    return server.create_authorization_response(grant_user=None)


@app.route('/oauth/token', methods=['POST'])
def issue_token():
    print('???????????')
    return server.create_token_response()


@app.route('/userinfo')
@require_oauth('profile')
def userinfo():
    return jsonify(generate_user_info(current_token.user, current_token.scope))

if __name__ == '__main__':
    server.init_app(app)
    # register it to grant endpoint
    server.register_grant(AuthorizationCodeGran)
    # register it to grant endpoint
    server.register_grant(grants.ImplicitGrant)
    server.register_grant(PasswordGrant)
    server.register_grant(grants.ClientCredentialsGrant)
    server.register_grant(OpenIDImplicitGrant)
    server.register_grant(AuthorizationCodeGrant, [OpenIDCode(require_nonce=True)])
    server.register_grant(OpenIDHybridGrant)

    bearer_cls = create_bearer_token_validator(db.session, Token)
    require_oauth.register_token_validator(bearer_cls())

    with app.app_context():
        db.create_all()
    PORT = int(os.environ.get('PORT', 8000))
    app.run(debug=True, host='0.0.0.0', port=PORT)
