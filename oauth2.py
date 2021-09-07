from models import db, User, Client, Token, AuthorizationCode
from authlib.integrations.flask_oauth2 import current_token
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
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2 import OAuth2Error


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

class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
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

def config_auth(app):
    server.init_app(app)
    # register it to grant endpoint
    server.register_grant(grants.ImplicitGrant)
    server.register_grant(PasswordGrant)
    server.register_grant(grants.ClientCredentialsGrant)
    server.register_grant(OpenIDImplicitGrant)
    server.register_grant(AuthorizationCodeGrant, [OpenIDCode(require_nonce=True)])
    server.register_grant(OpenIDHybridGrant)

    bearer_cls = create_bearer_token_validator(db.session, Token)
    require_oauth.register_token_validator(bearer_cls())

    return 'Done!'
