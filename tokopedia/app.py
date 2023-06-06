from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
import json
import os
import bcrypt
import jwt
import firebase_admin
from firebase_admin import credentials, firestore
from functools import wraps
import datetime
from tokped import tokopedia
from argparse import ArgumentParser
from os import system
app = Flask(__name__)
CORS(app)  # <-- This line allows CORS for all routes and origins

# Firebase Admin SDK configuration
cred = credentials.Certificate("/home/ssudo/Matkul/kripto-scrape/tokopedia/kripto-scraper-firebase-adminsdk-i77qf-c5d6bd8cac.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

app.config["SECRET_KEY"] = "inisaltkey"


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "Authorization" in request.headers:
            bearer_token = request.headers["Authorization"]
            token = bearer_token.split(" ")[1]

        if not token:
            return jsonify({"message": "Token is missing"}), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = data["username"]
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/register", methods=["POST"])
def register():
    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Save the username and hashed password to Firebase Firestore
    try:
        user_data = {"username": username, "password": hashed_password.decode("utf-8")}
        db.collection("users").add(user_data)
        return jsonify({"message": "User registered successfully"}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    # Retrieve the user from Firebase Firestore
    users_ref = db.collection("users").where("username", "==", username)
    users = users_ref.get()

    if len(users) == 0:
        return jsonify({"message": "Invalid username or password"}), 401

    user_data = users[0].to_dict()
    stored_password = user_data["password"]

    # Compare the hashed password with the password provided using bcrypt.checkpw()
    if bcrypt.checkpw(password.encode("utf-8"), stored_password.encode("utf-8")):
        expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        payload = {"username": username, "exp": expiration_time}
        token = jwt.encode(payload, app.config["SECRET_KEY"])
        return jsonify({"token": token})


    return jsonify({"message": "Invalid username or password"}), 401

@app.route("/user", methods=["GET"])
@token_required
def user(current_user):
    return jsonify({"message": "Valid token", "username": current_user}), 200


@app.route("/scrape", methods=["POST"])
@token_required
def scrape(current_user):  # Add current_user parameter
    toko = request.json.get("toko")
    file_type = int(request.json.get("file", 2))
    data = int(request.json.get("data", 0))
    print(f"toko: {toko}, file_type: {file_type}, data: {data}")

    if toko is None:
        return json.dumps({"error": "Toko name not provided"})

    try:
        parser = ArgumentParser(description='Tokopedia Downloader URL')
        parser.add_argument('-T', '--toko', dest='toko', type=str, help='nama toko yang ada di tokopedia')
        parser.add_argument('-F', '--file', dest='file', type=int, help='simpan file ke (1: json / 2: csv)')
        parser.add_argument('-D', '--data', dest='data', type=int, help='tampilkan data (0: false / 1: true)')
        args = parser.parse_args(['--toko', toko, '--file', str(file_type), '--data', str(data)])

        process = tokopedia(args.toko, args.data, args.file)
    except KeyboardInterrupt:
        exit(0)

    # Assuming the process generates a file in a directory named as the toko
    # and the file is named as toko_[produk].json
    file_path = os.path.join(toko, f"{toko}_[produk].json")

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return json.dumps({"error": "File not found"})


if __name__ == "__main__":
    app.run(debug=True)
