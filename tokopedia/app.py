from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import firebase_admin
from firebase_admin import credentials, firestore
from functools import wraps
import datetime
import pyotp
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from argparse import ArgumentParser
from tokped import tokopedia

app = Flask(__name__)
CORS(app)

cred = credentials.Certificate("./kripto-scraper-firebase-adminsdk-i77qf-c5d6bd8cac.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

app.config["SECRET_KEY"] = "inisaltkey"

sender_address = 'inilhoits2023@gmail.com'
sender_pass = 'sqmthhfqxlspexzg'

temp_users = {}

def send_email(subject, body, to):
    mail_content = body
    receiver_address = to

    message = MIMEMultipart()
    message['From'] = sender_address
    message['To'] = receiver_address
    message['Subject'] = subject

    message.attach(MIMEText(mail_content, 'plain'))

    session = smtplib.SMTP('smtp.gmail.com', 587)
    session.starttls()
    session.login(sender_address, sender_pass)
    text = message.as_string()
    session.sendmail(sender_address, receiver_address, text)
    session.quit()

    return 'Mail Sent'

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
            data = jwt.decode(token, app.config["SECRET_KEY"].encode("utf-8"), algorithms=["HS256"])
            current_user = data["username"]
        except jwt.exceptions.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid"}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def generate_otp_secret():
    base32_secret = pyotp.random_base32()
    return base32_secret

def generate_otp(base32_secret):
    totp = pyotp.TOTP(base32_secret)
    return totp.now()

def generate_expiration_time(minutes=30):
    return datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes)

def register_user(username, password, email):
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    otp_secret = generate_otp_secret()
    otp = generate_otp(otp_secret)
    otp_generated_time = datetime.datetime.now()

    temp_users[username] = {
        "username": username,
        "password": hashed_password.decode("utf-8"),
        "email": email,
        "otp_secret": otp_secret,
        "otp": otp,
        "otp_generated_time": otp_generated_time
    }

    send_email('Your OTP', f'Your OTP is {otp}', email)

@app.route("/register", methods=["POST"])
def register():
    username = request.json.get("username")
    password = request.json.get("password")
    email = request.json.get("email")

    if not username or not password or not email:
        return jsonify({"message": "Missing username, password, or email"}), 400

    register_user(username, password, email)

    return jsonify({"message": "OTP sent to your email"}), 200

@app.route("/verify_register", methods=["POST"])
def verify_register():
    username = request.json.get("username")
    otp = request.json.get("otp")

    if not username or not otp:
        return jsonify({"message": "Missing username or OTP"}), 400

    user_data = temp_users.get(username)
    if user_data:
        current_time = datetime.datetime.now()
        time_difference = current_time - user_data["otp_generated_time"]
        if time_difference.total_seconds() <= 1800:  # 30 minutes in seconds
            try:
                db.collection("users").add({
                    "username": username, 
                    "password": user_data["password"], 
                    "email": user_data["email"], 
                    "otp_secret": user_data["otp_secret"]
                })
                del temp_users[username]
                return jsonify({"message": "User registered successfully"}), 200
            except Exception as e:
                return jsonify({"message": str(e)}), 500
        else:
            return jsonify({"message": "OTP has expired"}), 401
    else:
        return jsonify({"message": "Invalid OTP"}), 401

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    users = [doc for doc in db.collection("users").where("username", "==", username).stream()]

    if not users:
        return jsonify({"message": "User not found"}), 404

    user_data = users[0].to_dict()
    stored_password = user_data["password"]

    if bcrypt.checkpw(password.encode("utf-8"), stored_password.encode("utf-8")):
        otp_secret = user_data["otp_secret"]
        otp = generate_otp(otp_secret)
        temp_users[username] = {"otp": otp}

        send_email('Your OTP', f'Your OTP is {otp}', user_data["email"])

        return jsonify({"message": "OTP sent to your email"}), 200
    else:
        return jsonify({"message": "Wrong password"}), 401

@app.route("/verify_login", methods=["POST"])
def verify_login():
    username = request.json.get("username")
    otp = request.json.get("otp")

    if not username or not otp:
        return jsonify({"message": "Missing username or OTP"}), 400

    user_data = temp_users.get(username)
    if user_data and user_data["otp"] == otp:
        del temp_users[username]

        token = jwt.encode({"username": username, "exp": generate_expiration_time()}, app.config["SECRET_KEY"].encode("utf-8"), algorithm="HS256")
        return jsonify({"token": token}), 200
    else:
        return jsonify({"message": "Invalid OTP"}), 401

@app.route("/user", methods=["GET"])
@token_required
def get_user(current_user):
    return jsonify({"username": current_user}), 200

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
