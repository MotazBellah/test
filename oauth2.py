from authlib.integrations.flask_oauth2 import AuthorizationServer
from models import db, User
# from models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token
from app import app

# def query_client(client_id):
#     return OAuth2Client.query.filter_by(client_id=client_id).first()
#
# def save_token(token_data, request):
#     if request.user:
#         user_id = request.user.get_user_id()
#     else:
#         # client_credentials grant_type
#         user_id = request.client.user_id
#         # or, depending on how you treat client_credentials
#         user_id = None
#     token = Token(
#         client_id=request.client.client_id,
#         user_id=user_id,
#         **token_data
#     )
#     db.session.add(token)
#     db.session.commit()

# or with the helper
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func
)

query_client = create_query_client_func(db.session, Client)
save_token = create_save_token_func(db.session, Token)

server = AuthorizationServer(
    app, query_client=query_client, save_token=save_token
)
