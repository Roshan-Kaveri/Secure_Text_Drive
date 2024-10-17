
from flask import Flask, request, jsonify, session, flash, Response

from password_encrypter import decrypt
import binascii
from mail_config import mail
from mail_settings import *
from otp_utils import generate_otp, send_otp_email, otp_storage, send_reset_email
import psycopg2

from flask import jsonify, request

from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.secret_key = 'abcdlala'
# Database connection details
hostname = 'postgresql-ascscs.alwaysdata.net'
database = 'ascscs_securedrive'
username = 'ascscs'
pwd = '@7sdDgVUuhCXjD6'
port_id = 5432

# Mail configuration
app.config['MAIL_SERVER'] = MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
app.config['MAIL_USE_SSL'] = MAIL_USE_SSL


mail.init_app(app)


def get_db_connection():
    return psycopg2.connect(
        host=hostname,
        dbname=database,
        user=username,
        password=pwd,
        port=port_id
    )

# Signup API
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not email or not password or not confirm_password:
        return jsonify({"error": "Email, password, and confirm password are required."}), 400

    if password != confirm_password:
        return jsonify({"error": "Passwords do not match."}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if the email already exists
        cur.execute('SELECT * FROM USERS WHERE email = %s', (email,))
        if cur.fetchone() is not None:
            return jsonify({"error": "Email already exists."}), 400

        # Insert new user into the database
        cur.execute('INSERT INTO USERS(email, password, auth) VALUES(%s, %s, %s)', (email, password, True))
        conn.commit()

        cur.close()
        conn.close()

        return jsonify({"message": "Signup Successful."}), 200
    except Exception as error:
        return jsonify({"error": str(error)}), 500

# Login API
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if the email and password match any entry in the database
        cur.execute('SELECT email, password, auth FROM USERS WHERE email = %s AND password = %s', (email, password))
        user = cur.fetchone()

        cur.close()
        conn.close()

        if user:
            session['email'] = user[0]
            session['auth'] = bool(user[2])  # Convert auth to a boolean

            if session['auth']:
                print('Login Successful! OTP sent.', 'success')
                gen_otp(user[0])  # Ensure gen_otp is defined correctly
                return jsonify({
                    "message": "OTP sent",
                    "email": session['email'],  # Include email
                    "auth": session['auth']     # Include auth
                }), 200
            else:
                print('Login Successful!', 'success')
                return jsonify({
                    "message": "Login Successful!",
                    "email": session['email'],  # Include email
                    "auth": session['auth']     # Include auth
                }), 200
        else:
            return jsonify({"error": "Invalid email or password"}), 400

    except Exception as error:
        return jsonify({"error": str(error)}), 500



# Assuming SECRET_KEY is used for encryption/decryption



@app.route('/api/forgot_password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    # Validate the email format
    if not email :
        return jsonify({"error": "Invalid email format"}), 400

    try:
        # Database connection and email checking
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT password FROM users WHERE email = %s', (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            # Note: Do not send the password via email for security reasons!
            # Instead, send a password reset link or token
            encrypted_password = user[0]
            decrypted_password = decrypt(encrypted_password, 23)
            print("decr ", decrypted_password)
            # Send email with the decrypted password
            send_reset_email(mail, email, decrypted_password)
            return jsonify({"email_found": "true", "message": "OTP sent to your email!"}), 200

        else:
            return jsonify({"error": "Email not found"}), 404

    except Exception as error:
        return jsonify({"error": str(error)}), 500


# OTP Generation Function
def gen_otp(email):
    otp = generate_otp()
    otp_storage[email] = otp
    print(otp_storage)
    session['unverified_email'] = email

    if send_otp_email(mail, email, otp):
        return jsonify({"message": "OTP sent successfully!"}), 200
    else:
        return jsonify({"error": "Failed to send OTP email"}), 500

@app.route('/api/auth', methods=['POST'])
def auth():
        data = request.json
        email = data.get('email')

        if not email:
            return jsonify({"error": "Session expired, please log in again."}), 401

        entered_otp = data.get('otp')

        stored_otp = otp_storage.get(email)
        print(stored_otp , " a " , entered_otp , " a ", email)

        if stored_otp == entered_otp:
            print("SUccesfull bhai")
            otp_storage.pop(email, None)
            session['email'] = email
            return jsonify({"message": "OTP verified successfully!"}), 200
        else:
            return jsonify({"error": "Invalid OTP. Please try again."}), 400

@app.route('/api/home', methods=['GET'])
def home():
    email = session.get('email')
    if email:
        return jsonify({"email": email}), 200
    else:
        return jsonify({"error": "Unauthorized access"}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    # Clear the user session
    session.clear()
    # Optionally, you can also add a print statement for logging
    print("User logged out successfully.")
    # Return a success message
    return jsonify({"message": "Logged out successfully."}), 200

@app.route('/api/toggle_2fa', methods=['POST'])
def toggle_2fa():
    data = request.json
    email = data.get('email')

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed."}), 500

    cur = conn.cursor()
    try:
        # Check if the email exists in the database
        cur.execute('SELECT auth FROM USERS WHERE email = %s', (email,))
        user = cur.fetchone()

        if user:
            new_auth_status = not user[0]  # Toggle the current auth status
            cur.execute('UPDATE USERS SET auth = %s WHERE email = %s', (new_auth_status, email))
            conn.commit()  # Commit the transaction

            # Print statement for logging
            print(f"Toggled 2FA for user {email}: New auth status is {'enabled' if new_auth_status else 'disabled'}.")
            return jsonify({
                "message": f"Auth status toggled to {'enabled' if new_auth_status else 'disabled'}.",
                "auth": new_auth_status
            }), 200
        else:
            return jsonify({"error": "User not found"}), 404

    except Exception as error:
        return jsonify({"error": str(error)}), 500
    finally:
        cur.close()
        conn.close()

# Route to handle file upload and storage in the database
# Route to handle file upload and storage in the database
@app.route('/api/upload_file', methods=['POST'])
def upload_file():
    try:
        # Get the data from the request
        print("CAAAAAAAAAAAAAAAAAA")
        data = request.json
        email = data.get('email')
        filename = data.get('filename')
        encrypted_content_hex = data.get('content')
        public_key_pem = data.get('public_key')
        encryption_method = data.get('encryption_method')  # New field for encryption method
        key_size = data.get('key_size')  # New field for key size
        print(email,filename,encrypted_content_hex,public_key_pem,encryption_method,key_size)
        # Check if email, filename, or encrypted content is missing
        if not email or not filename or not encrypted_content_hex or not public_key_pem or not encryption_method or not key_size:
            return jsonify({"error": "Missing required fields"}), 400

        # Decode the hex-encoded encrypted content back to bytes
        try:
            encrypted_content = binascii.unhexlify(encrypted_content_hex)
        except binascii.Error:
            return jsonify({"error": "Invalid encrypted content format"}), 400

        # Store the encrypted content and public key into the database
        # Assuming you already have a 'filecon' table with columns: email, fpath, fcon, pubkey, encryption_method, key_size
        conn = get_db_connection()
        cur = conn.cursor()

        insert_filecon = '''
            INSERT INTO filecon (email, fpath, fcon, pubkey, encryption_method, key_size) 
            VALUES (%s, %s, %s, %s, %s, %s)
        '''
        cur.execute(insert_filecon, (email, filename, encrypted_content, public_key_pem, encryption_method, key_size))
        conn.commit()

        cur.close()
        conn.close()

        return jsonify({"message": "File uploaded and stored successfully"}), 200

    except Exception as error:
        print("Error during file upload:", error)
        return jsonify({"error": "An error occurred during file upload"}), 500

@app.route('/api/retrieve_file', methods=['POST'])
def retrieve_file():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    try:
        # Database connection
        conn = get_db_connection()
        cur = conn.cursor()

        # Retrieve all file info based on email
        cur.execute('SELECT fpath, fcon, pubkey, key_size FROM filecon WHERE email = %s', (email,))
        file_records = cur.fetchall()  # Fetch all records

        if not file_records:
            return jsonify({"error": "No files found for this email"}), 404

        files = []
        for record in file_records:
            file_path = record[0]
            encrypted_content = record[1]
            pukey = record[2]
            ks = record[3]
            print(file_path, encrypted_content, "<--")
            decrypted_content = encrypted_content  # Decrypt if necessary
            files.append({
                "filename": file_path,
                "content": decrypted_content,
                "public_key": pukey,
                "key_size": ks
                # Include the decrypted content if necessary
            })

        return jsonify({"files": files}), 200  # Return the list of files in JSON format

    except Exception as error:
        return jsonify({"error": str(error)}), 500

    finally:
        cur.close()
        conn.close()

safe_mode = False
@app.route('/api/delete_all_filecon', methods=['DELETE'])
def delete_all_filecon():
    if safe_mode:  # Check if safe_mode is enabled
        return jsonify({"error": "Deletion is not allowed in safe mode."}), 403

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # SQL query to delete all rows in the filecon table
        cur.execute('DELETE FROM filecon;')
        conn.commit()

        cur.close()
        conn.close()

        return jsonify({"message": "All contents deleted successfully."}), 200

    except Exception as error:
        print("Error during deletion:", error)
        return jsonify({"error": "An error occurred during deletion."}), 500


if __name__ == '__main__':
    app.run(debug=True,port=8000)