import os
import time
from flask import Flask, jsonify, request, url_for, render_template, session, redirect
from models import db, User, Client, Token, AuthorizationCode
from authlib.integrations.flask_oauth2 import current_token
from oauth2 import *


app = Flask(__name__)
app.secret_key = 'super secret key'


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['OAUTH2_REFRESH_TOKEN_GENERATOR'] = True

db.init_app(app)


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
    user = get_user()
    if not user:
        return redirect(url_for('home', next=request.url))
    if request.method == 'GET':
        user = get_user()

        grant = server.validate_consent_request(end_user=user)
        return render_template(
            'authorize.html',
            grant=grant,
            user=user,
            client='',
            scopes='',
        )
    confirmed = request.form['confirm']
    if confirmed:
        # granted by resource owner
        return server.create_authorization_response(grant_user=user)
    # denied by resource owner
    return server.create_authorization_response(grant_user=None)


@app.route('/oauth/token', methods=['POST'])
def issue_token():
    return server.create_token_response()


@app.route('/userinfo')
@require_oauth('profile')
def userinfo():
    return jsonify(generate_user_info(current_token.user, current_token.scope))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    config_auth(app)
    PORT = int(os.environ.get('PORT', 8000))
    app.run(debug=True, host='0.0.0.0', port=PORT)
