"""Angel Island Server"""

import os
import hashlib
import http.client as http_client
import logging
import random
import secrets
from datetime import datetime
from http import HTTPStatus
from pprint import pprint
from collections import Counter
import ssl
import socket

import mongoengine
from flask import Flask, request, jsonify, redirect, abort
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_mongoengine import MongoEngine # install via pip install git+https://github.com/idoshr/flask-mongoengine.git@1.0.1
from mongoengine import StringField, DictField, ListField, IntField, FloatField

http_client.HTTPConnection.debuglevel = 0



# To generate a new Self-Signed Certificate:
# openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem -config san.cnf
# Reference: https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs

logging.basicConfig(
    format="%(levelname)s [%(asctime)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.DEBUG  # Can be DEBUG, INFO
)

# mongoengine.disconnect()
# mongoengine.connect("angelisland_db")

mongoengine.disconnect(alias='default')

# mongoengine.connect("angelisland_db", alias='default')

app = Flask(__name__)

# specify MongoDB location details
# app.config['MONGODB_SETTINGS'] = {
#     'db': 'angelisland_db',
#     'host': 'angelisland.melbell.uk',
#     'port': 27017,
# }
app.config['MONGODB_SETTINGS'] = {
    'db': 'angelisland_db',
    'host': "localhost",
    'port': 27017,
}
app.secret_key = 'some_key'
db = MongoEngine()
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

our_app_iters = 600_000

# working directory
DIR_PATH = os.path.dirname(os.path.realpath(__file__))

# Password handling
def set_password_hash(password):
    """Sets password hash and salt when setting a password"""
    password_binary = str.encode(password)
    password_salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", password_binary, password_salt.encode(), our_app_iters)
    return password_hash.hex(), password_salt


def get_password_hash(password, salt):
    """re-generates password hash when logging into account"""
    password_binary = str.encode(password)
    salt_binary = salt.encode()
    password_hash = hashlib.pbkdf2_hmac("sha256", password_binary, salt_binary, our_app_iters)
    return str(password_hash.hex())


class User(db.Document):
    """Class to handle users in MongoDB"""
    username = StringField()
    password_hash = StringField()
    password_salt = StringField()
    email = StringField()
    # collection = DictField()
    # parties = ListField(max_length=5)
    friends = ListField()
    direct_messages = DictField()
    # pve_battles = IntField(default=0, min_value=0)
    # pve_losses = IntField(default=0, min_value=0)
    # pvp_battles = IntField(default=0, min_value=0)
    # pvp_losses = IntField(default=0, min_value=0)

    def to_json(self):
        """Converts to json"""
        return {"username": self.username,
                "email": self.email}

    def is_authenticated(self):
        """Returns authenticated"""
        return True

    def is_active(self):
        """Returns active"""
        return True

    def is_anonymous(self):
        """Returns anonymous"""
        return False

    def get_id(self):
        """Returns ID"""
        return str(self.id)


@app.route('/', methods=['PUT'])
def create_new_user():
    """creates new user account"""
    record = request.json
    username = record['username']
    email = record['email']
    try:
        # Check whether account already exists
        if User.objects(username=username).first():
            return jsonify({'Account creation error': 'Username already exists'})
        try:
            password_hash, password_salt = set_password_hash(record['password'])
            user = User(username=username,
                        password_hash=password_hash,
                        password_salt=password_salt,
                        email=email,)
            user.save()
            return jsonify({'success': 'account created'})
        except Exception as e:
            print(e)
            #     print("account error")
            #     return jsonify(({'error': 'account error'}))
            return jsonify({'error': f'account creation error {e}'})
    except:
        return jsonify({'error': 'account creation error'})


@app.route('/', methods=['POST'])
# @login_required
def query_records():
    """Queries user data"""
    record = request.json
    username = record['username']
    try:
        user = User.objects(username=username).first()
        if not user:
            return jsonify({'error': 'data not found'})

        data = {
            "username": user.username,
        }
        return jsonify(data)
    except Exception as e:
        print(e)
        return jsonify({'error': 'data not found'})


@app.route("/login", methods=['POST'])
def user_login():
    """Handles user login info"""
    info = request.json
    username = info['username']
    password = info['password']

    try:
        named_account = User.objects(username=username).first()
        salt = named_account.password_salt

        password_hash = get_password_hash(password, salt)
        hashed_account = User.objects(username=username,
                                      password_hash=password_hash).first()
        if hashed_account:
            login_user(hashed_account)
            return jsonify({'success': f'User {username} logged in'})

    except Exception as e:
        return jsonify({'failure': f'Username or password is incorrect: {e}'})


@app.route('/logout', methods=['POST'])
def logout():
    """Handles logout case"""
    logout_user()
    return jsonify(**{'result': 200,
                      'data': {'message': 'logout success'}})


@app.route('/user_info', methods=['POST'])
def user_info():
    """Gets current user details"""
    if current_user.is_authenticated:

        user = User.objects(username=current_user.username).first()
        data = {
            "username": user.username,
            "email": user.email,
            "friends": user.friends,
            "direct_messages": user.direct_messages
        }
        # pprint(data)
        resp = {"result": 200,
                "data": data}
    else:
        resp = {"result": 401,
                "data": {"message": "user not logged in"}}
    return jsonify(**resp)


@login_manager.user_loader
def load_user(user_id):
    """Loads user"""
    return User.objects(id=user_id).first()


@app.route('/update', methods=['POST'])
@login_required
def update_account():
    """Handles updating email and password"""
    # print("does it reach here?")
    username = current_user.username

    info = request.json
    old_password = info['old_password']
    new_password = info['new_password']
    new_password_confirm = info['new_password_confirm']

    # Confirms current password of logged-in account
    named_account = User.objects(username=username).first()
    salt = named_account.password_salt
    old_password_hash = get_password_hash(old_password, salt)
    hashed_account = User.objects(username=username,
                                  password_hash=old_password_hash).first()
    if not hashed_account:
        return jsonify({'error': 'data not found'})
    elif new_password != new_password_confirm:
        return jsonify({'error': 'new passwords do not match'})
    # print("does it reach here?")

    # sets new password hash and salt
    password_hash, password_salt = set_password_hash(new_password)
    hashed_account.update(email=info['email'],
                          password_hash=password_hash,
                          password_salt=password_salt)
    # print("does it reach here?")
    return jsonify(hashed_account.to_json())


@app.route('/', methods=['DELETE'])
@login_required
def delete_account():
    """Handles account deletion case"""
    username = current_user.username
    user = User.objects(username=username).first()
    if not user:
        return jsonify({'error': 'data not found'})
    user.delete()  # may want to change to "active=False" instead
    return jsonify(user.to_json())


@login_manager.unauthorized_handler
def unauthorized():
    """Handles unauthorised access case"""
    if request.blueprint == 'api':
        print("Unauthorised, redirecting to login")
        abort(HTTPStatus.UNAUTHORIZED)
    return redirect("login")


@app.route("/new_friend", methods=['POST'])
@login_required
def post_new_friend():
    """Post new friend to friends list"""
    info = request.json
    if info.get("new_friend"):
        new_friend = info.get("new_friend")
        username = current_user.username
        user = User.objects(username=username).first()
        friends = user.friends
        if new_friend not in friends:
            friends.append(new_friend)
            user.update(friends=friends)
            return jsonify({'Successfully added new friend': new_friend})
        return jsonify({'Failed to add new friend': f"Already friends with {new_friend}"})
    return jsonify({'Failed to add new friend': "No friend specified"})


@app.route("/remove_friend", methods=["POST"])
@login_required
def post_remove_friend():
    """Remove entry from friends list"""
    info = request.json
    if info.get("remove_friend"):
        remove_friend = info.get("remove_friend")
        username = current_user.username
        user = User.objects(username=username).first()
        friends = user.friends
        if remove_friend not in friends:
            return jsonify({'Failed to remove friend': "f{remove_friend} not in friends list"})
        friends.pop(friends.index(remove_friend))
        user.update(friends=friends)
        return jsonify({'Successfully removed friend': remove_friend})
    return jsonify({'Failed to remove friend': "No friend specified"})


@app.route("/direct_message", methods=["POST"])
@login_required
def post_direct_message():
    """Sends direct message to specified account"""
    info = request.json
    username = current_user.username
    user = User.objects(username=username).first()
    recipient = info.get("recipient")
    message = info.get("message")
    timestamp = datetime.now()  # use pytz in client to get different timezone data
    # print("1 - does it get here?")

    # to_insert = dict()
    # to_insert[party_number] = party_members
    # set_to_insert = dict((("set__parties__%s" % k, v) for k, v in to_insert.items()))
    # account.update(**set_to_insert)

    try:
        # succeeds if conversation already exists
        existing_messages = user.direct_messages[recipient]
        existing_messages.append((timestamp, username, message))

        to_insert = dict()
        to_insert[recipient] = existing_messages
        set_to_insert = dict((("set__direct_messages__%s" % k, v) for k, v in to_insert.items()))
        user.update(**set_to_insert)

        print("2 - does it get here?")
    except:
        # succeeds if new conversation needs to be started

        # user.direct_messages[recipient]
        existing_messages = [(timestamp, username, message)]

        # existing_messages = user.direct_messages[recipient]
        # existing_messages.append((username, message))

        to_insert = dict()
        to_insert[recipient] = existing_messages
        set_to_insert = dict((("set__direct_messages__%s" % k, v) for k, v in to_insert.items()))
        user.update(**set_to_insert)

        print("3 - does it get here?")
    result = process_direct_message(username, recipient, message, timestamp)
    return jsonify(result)


def process_direct_message(sender: str, recipient: str, message: str, timestamp: datetime):
    """Handles passing direct message from sender to recipient"""
    try:
        addressee = User.objects(username=recipient).first()
    except Exception as e:
        return {'Direct message failed': f"Could not process message: {e}"}
    # print(addressee.objects.get("direct_messages")[recipient])
    try:
        try:
            # succeeds if conversation already exists
            try:
                existing_messages = addressee.direct_messages[sender]

                # existing_messages = addressee.objects.get("direct_messages")[recipient]
                existing_messages.append((timestamp, sender, message))
            except Exception as e:
                print(f"issue loading existing messages: {e}")
                raise
                # return None
            print("appends messages")

            to_insert = dict()
            to_insert[sender] = existing_messages  # (sender, message)
            set_to_insert = dict((("set__direct_messages__%s" % k, v) for k, v in to_insert.items()))
            addressee.update(**set_to_insert)
        except:
            # succeeds if new conversation needs to be started
            # addressee.direct_messages[sender] = [(sender, message)]
            existing_messages = [(timestamp, sender, message)]

            print("creates new conversation")

            to_insert = dict()
            to_insert[sender] = existing_messages
            set_to_insert = dict((("set__direct_messages__%s" % k, v) for k, v in to_insert.items()))
            addressee.update(**set_to_insert)
        return {'Direct message success': "Message processed"}
    except:
        return {'Direct message failed': "Could not process message"}


# Start the app
def main():
    """Runs the server software"""

    # Load CA certificate
    ssl_settings = ssl.create_default_context()
    ssl_settings.load_verify_locations(DIR_PATH+"/cert.pem")
    # ease python policy towards self-signed certificates
    ssl_settings.verify_flags = ssl_settings.verify_flags & ~ssl.VERIFY_X509_STRICT
    # load client certificate
    ssl_settings.load_cert_chain(certfile=DIR_PATH+'/cert.pem', keyfile=DIR_PATH+'/key.pem')

    print("running...")
    app.run(port=5000, ssl_context=ssl_settings, debug=True)


if __name__ == '__main__':
    main()
