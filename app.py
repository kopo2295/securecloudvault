import os
import pyotp
import qrcode
import io
import base64
import logging
import smtplib
import socket

from flask import Flask
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
from cryptography.fernet import Fernet
from dotenv import load_dotenv
load_dotenv()

from cryptography.fernet import Fernet
#print(Fernet.generate_key().decode())

def allowed_file(filename):
    return '.' in filename and \
             filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

logging.basicConfig(
    filename='audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
ALERT_EMAIL = os.getenv("ALERT_EMAIL")
MASTER_KEY = os.getenv("MASTER_KEY")

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'zip'}
app= Flask(__name__)
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.getenv("FLASK_SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)


def send_alert_email(subject, body):
    msg = EmailMessage ()
    msg['Subject'] = subject
    msg['from' ] = SMTP_USERNAME
    msg['To' ] = ALERT_EMAIL
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
            smtp.send_message(msg)
        logging.info(f"Alert email sent: {subject}")
    except Exception as e:
        logging.error(f"Failed to send alert email: {e}")


# user model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    totp_secret =db.Column(db.String(16))
    encryption_key = db.Column(db.String(44))

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        files = File.query.filter_by(user_id=user.id).all()
        return render_template('home.html', username=user.username, files=files)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']


        # check if user exist
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return 'User already exist!'


        # hash the password and save user
        hashed_pw = generate_password_hash(password)
        totp_secret = pyotp.random_base32()
        user_key = Fernet.generate_key()
        master_fernet = Fernet(MASTER_KEY.encode())
        encrypted_user_key = master_fernet.encrypt(user_key).decode()

        new_user = User(
            username=username,
            password_hash=hashed_pw,
            totp_secret=totp_secret,
            encryption_key=encrypted_user_key
        )

        db.session.add(new_user)
        db.session.commit()
        session['temp_username'] = username
        return redirect(url_for('mfa_setup'))


    return render_template('register.html')


@app.route('/mfa-setup')
def mfa_setup():
    username =session.get('temp_username')
    if not username:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for('login'))

    totp = pyotp.TOTP(user.totp_secret)
    otp_url = totp.provisioning_uri(name=username, issuer_name="SecureCloudVault")


    #Generate QR code for authenticator app
    qr_img = qrcode.make(otp_url)
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    qr_data = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('mfa_setup.html', qr_data=qr_data, secret=user.totp_secret)

@app.route('/files')
def uploaded_files():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    files = File.query.filter_by(user_id=session['user_id']).all()
    return render_template('files.html', files=files)



@app.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    user_id = session.get('pre_2fa_user')
    if not user_id:
        return redirect(url_for('login'))


    user = User.query.get(user_id)
    if request.method == 'POST':
        code = request.form['code']
        totp = pyotp.TOTP(user.totp_secret)


        if totp.verify(code):
            session.pop('pre_2fa_user', None)
            session['user_id'] = user.id
            session['username'] = user.username
            logging.info(f"User '{user.username}' successfully logged in with MFA.")
            return redirect(url_for('index'))
        else:
            logging.warning(f"Invalid MFA code for user ID {user_id}")
            send_alert_email(
                "MFA Alert",
                f"User ID {user_id} failed MFA verification from IP {request.remote_addr}"
            )
            return'Invalid MFA code'


    return  render_template('mfa_verify.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user=User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session.pop('failed_logins', None)
            session['pre_2fa_user'] = user.id
            logging.info(f"User'{username}' passed password check, awaiting MFA.")
            session['username'] = user.username
            return redirect(url_for('mfa_verify'))
        else:
            session['failed_logins'] = session.get('failed_logins',0) + 1
            logging.warning(f"Failed login #{session['failed_logins']} for {username}'")
            if session['failed_logins'] >=5:
                alert_msg = f" ALERT :5 failed login attempts for user'{username}' from IP {request.remote_addr}"
                logging.critical(alert_msg)
                send_alert_email("Brute-force detected", alert_msg)
                return 'Too many failed attempts. Alert has been sent to administrator.'
            return 'Invalid credentials'

    return render_template('login.html')


@app.route('/upload', methods=['GET','POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user =User.query.get(session['user_id'])

    if request.method == 'POST':
        file = request.files['file']
        if file.filename == '':
             return 'NO selected file', 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            user_id = session['user_id']
            user_folder = os.path.join('uploads', str(session['user_id']))
            os.makedirs(user_folder, exist_ok=True)
            filepath = os.path.join(user_folder, filename)

            #encrypt before saving
            data = file.read()
            master_fernet =Fernet(MASTER_KEY.encode())
            user_key = master_fernet.decrypt(user.encryption_key.encode())
            fernet = Fernet(user_key)
            encrypted_data = fernet.encrypt(data)

            with open(filepath, 'wb') as f:
                f.write(encrypted_data)

            #save file record
            new_file = File(filename=filename, user_id=user_id)
            db.session.add(new_file)
            db.session.commit()

            logging.info(f"User'{user.username}' uploaded file '{filename}'")
            return redirect(url_for('index'))
        return 'File type not allowed.'

    return '''
    <h2>Upload a file</h2>
    <form method="post" enctype="multipart/form-data">
         <input type="file" name="file" required>
         <input type="submit" value="Upload">
    </form>
    <a href="/">Back to Dashboard</a>
    '''

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file_record = File.query.get(file_id)
    if not file_record or file_record.user_id != session['user_id']:
        return 'Access Denied'

    user = User.query.get(session['user_id'])
    file_path = os.path.join('uploads', str(user.id), file_record.filename)

    if not os.path.exists(file_path):
        return 'File not found'

    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    try:
        master_fernet = Fernet(MASTER_KEY.encode())
        user_key = master_fernet.decrypt(user.encryption_key.encode())
        fernet = Fernet(user_key)
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        logging.error(f"Decryption failed for user '{user.username}': {e}")
        return 'Decryption failed'

    #send decrypted file
    from flask import Response
    logging.info(f"user '{user.username}' downloaded file '{file_record.filename}'" )


    return Response(
        decrypted_data,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={file_record.filename}"}
    )


@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown user')
    logging.info(f"User '{username}' logged out.")
    session.clear()
    return redirect(url_for('login'))

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

if __name__=='__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)


