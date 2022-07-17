from functools import wraps
from hmac import compare_digest
from secrets import token_urlsafe
from flask import Flask, abort, make_response, redirect, render_template, request, session

SESSIONID_COOKIE_NAME = 'csrf_newbie_sessionid'
CSRF_TOKEN_COOKIE_NAME = 'csrf_newbie_token'
CSRF_TOKEN_HEADER_NAME = 'x-csrf-newbie-token'

app = Flask(__name__)
app.secret_key = "csrf-newbie"
app.session_cookie_name = SESSIONID_COOKIE_NAME


def check_csrf_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        request_token = request.form.get('csrf_token') or request.headers.get(CSRF_TOKEN_HEADER_NAME)
        session_token = session.get('csrf_token')

        if request_token and session_token and compare_digest(request_token, session_token):
            return f(*args, **kwargs)
        else:
            return abort(403)

    return decorated_function


@app.route("/", methods=["GET"])
def index():
    error_message = None
    if 'error_message' in session:
        error_message = session['error_message']
        del session['error_message']

    next_csrf_token = _refresh_csrf_token()
    response = make_response(render_template("app.html", error_message=error_message))
    if next_csrf_token:
        response.set_cookie(CSRF_TOKEN_COOKIE_NAME, next_csrf_token)

    return response


@app.route("/login", methods=["POST"])
@check_csrf_token
def login():
    next_csrf_token = _refresh_csrf_token(force=True)
    response = make_response(redirect('/'))
    response.set_cookie(CSRF_TOKEN_COOKIE_NAME, next_csrf_token)

    id = request.form.get("id")
    password = request.form.get("password")
    if not _authentication(id, password):
        session['error_message'] = 'Login failed.'
        return response

    session['username'] = id
    return response


@app.route("/logout", methods=["POST"])
@check_csrf_token
def logout():
    session.clear()

    next_csrf_token = _refresh_csrf_token(force=True)
    response = make_response(redirect('/'))
    response.set_cookie(CSRF_TOKEN_COOKIE_NAME, next_csrf_token)

    return response


@app.route("/username", methods=["POST"])
@check_csrf_token
def change_username():
    username = request.form.get('username')
    session['username'] = username

    response = make_response(redirect('/'))

    return response

def _refresh_csrf_token(force = False):
    if force or 'csrf_token' not in session:
        next_token = token_urlsafe()

        session['csrf_token'] = next_token
        return next_token

    return None


def _authentication(id, password):
    auth_table = {
        "user1": "password1",
        "user2": "password2",
        "user3": "password3",
    }

    return auth_table.get(id) == password
