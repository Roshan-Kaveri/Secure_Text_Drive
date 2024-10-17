import binascii
import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import Blueprint, render_template, request, Response,  session, flash, redirect, url_for, jsonify
import requests
from rsa_utils import generate_rsa_key_pair, rsa_encrypt, serialize_public_key
from password_encrypter import encrypt , decrypt
from rsa_utils import rsa_decrypt

views = Blueprint('views', __name__)

# Backend server URL
server_url = 'http://127.0.0.1:8000/api'

# Signup route
@views.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = encrypt(request.form.get('password'),23)
        confirm_password = encrypt(request.form.get('confirm_password'),23)

        # Send signup request to backend
        try:
            response = requests.post(f'{server_url}/signup', json={
                "email": email,
                "password": password,
                "confirm_password": confirm_password
            })

            if response.status_code == 200:
                flash('Signup Successful! You can now log in.', 'success')
                return redirect(url_for('views.login'))
            else:
                error_data = response.json()
                return render_template('signup.html', error=error_data.get("error", "Unknown error"))
        except requests.exceptions.RequestException as e:
            return render_template('signup.html', error=f'Failed to connect to the server: {str(e)}')

    return render_template('signup.html')

# Login route
@views.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = encrypt(request.form.get('password'), 23)

        # Send login request to backend
        try:
            response = requests.post(f'{server_url}/login', json={
                "email": email,
                "password": password
            })

            if response.status_code == 200:
                user_data = response.json()

                # Store user details in session

                session['auth'] = user_data.get('auth')

                if session['auth']:  # Check if auth is 1
                    session['un_email'] = user_data.get('email')
                    flash('Login Successful! OTP sent.', 'success')
                    return render_template('auth.html')  # Open auth.html directly
                else:
                    session['email'] = user_data.get('email')
                    flash('Login Successful!', 'success')
                    return redirect(url_for('views.homes'))  # Redirect to homes if auth is not 1

            else:
                error_data = response.json()
                return render_template('login.html', error=error_data.get("error", "Unknown error"))

        except requests.exceptions.RequestException as e:
            return render_template('login.html', error=f'Failed to connect to the server: {str(e)}')

    return render_template('login.html')

# Forgot Password route
@views.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    # Get the email from the URL query parameter
    email = request.args.get('email')

    if email:
        # Send forgot password request to backend
        try:
            response = requests.post(f'{server_url}/forgot_password', json={
                "email": email
            })

            if response.status_code == 200:
                flash('OTP sent to your email!', 'success')
                return redirect(url_for('views.home'))
            else:
                error_data = response.json()
                return render_template('forgot_pass.html', error=error_data.get("error", "Unknown error"))
        except requests.exceptions.RequestException as e:
            return render_template('forgot_pass.html', error=f'Failed to connect to the server: {str(e)}')

    return render_template('forgot_pass.html', error='Email not provided')


# Home route
@views.route('/', methods=['GET', 'POST'])
def homes():
    email = session.get('email')
    auth = session.get('auth')

    try:
        # Make a POST request to retrieve files
        response = requests.post(f'{server_url}/retrieve_file', json={
            "email": email,
            "auth": auth  # Include authentication status in the request
        })

        if response.status_code == 200:
            data = response.json()
            file_list = data.get('files', [])  # Extract the list of files (name and content)

            # Store file_list in session or pass to the frontend as context
            session['file_list'] = file_list
            print(file_list)
            # You can now render the homepage template and pass the file list to the frontend
            return render_template('home.html',  email=email, auth=auth, file_list=file_list)

        else:
            # Handle errors returned by the server
            error_data = response.json()
            error_message = error_data.get("error", "Failed to retrieve files.")
            return render_template('home.html',  email=email, auth=auth, file_list=[])

    except requests.exceptions.RequestException as e:
        # Handle network-related errors
        return render_template('home.html', email=email, auth=auth, file_list=[])

    except requests.exceptions.RequestException as e:
        return {"error": f'Failed to connect to the server: {str(e)}'}, 500

    return render_template('home.html', email=email, auth=auth, file_list=file_list)



@views.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    # Retrieve file_list from session
    file_list = session.get('file_list', [])

    # Find the file data based on the filename
    file_data = next((file for file in file_list if file['filename'] == filename), None)

    if file_data is None:
        return {"error": "File not found"}, 404

    # Extract content and keys
    public_key_pem = file_data['public_key']
    file_content = file_data['content']
    file_content = re.sub(r'\\x', '', file_content)
    print(file_content)
    # Decode the content from its escaped hexadecimal format

    # Load the public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    print(public_key)
    # Decrypt the content using the RSA public key
    decrypted_content = file_content
    # = decrypt(binascii.unhexlify(file_content),public_key)
    print(file_data , "\n))", decrypted_content)



    # Ensure decrypted_content is in bytes
    #if isinstance(decrypted_content, str):
    #    decrypted_content = decrypted_content.encode('utf-8')  # Convert string to bytes if necessary

    print(decrypted_content)
    # Serve the content as a downloadable file
    response = Response(decrypted_content, mimetype='text/plain')
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"  # No .txt here if already included

    return response


@views.route('/logout', methods=['GET'])
def logout():
    # Clear the session to log the user out
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('views.homes'))  # Redirect to the home page or login page
@views.route('/api/toggle_2fa', methods=['POST'])
def toggle_2fa():
    email = request.json.get('email')

    # Check if the email exists in the session
    if email != session.get('email'):
        return jsonify({"error": "Unauthorized access."}), 403

    # Send the toggle request to the backend server running on port 8000
    try:
        response = requests.post(f'{server_url}/toggle_2fa', json={  # Corrected the backend route to /toggle_2fa
            "email": email
        })

        if response.status_code == 200:
            session['auth'] = not session['auth']  # Toggle the 2FA status in the session
            return jsonify({"message": "2FA status updated successfully."}), 200
        else:
            error_data = response.json()
            return jsonify({"error": error_data.get("error", "Failed to update 2FA status.")}), response.status_code

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f'Failed to connect to the server: {str(e)}'}), 500

@views.route('/auth', methods=['GET', 'POST'])
def auth():
    # Your authentication logic here
    return render_template('auth.html')
# views.py
@views.route('/verify_otp', methods=['POST'])
def verify_otp():
    combined_otp = request.form.get('otp')  # Get the complete OTP

    # Send the OTP to the backend running at port 8000 for verification
    try:
        response = requests.post(f'{server_url}/auth', json={"otp": combined_otp,"email": session.get('un_email')})

        if response.status_code == 200:
            session['email'] = session.get('un_email')
            flash('Login successful!', 'success')
            return redirect(url_for('views.homes'))  # Redirect to home on success
        else:
            error_data = response.json()
            flash(error_data.get("error", "Invalid OTP. Please try again."), 'error')
            return redirect(url_for('views.login'))  # Redirect back to login on error

    except requests.exceptions.RequestException as e:
        flash(f'Failed to connect to the server: {str(e)}', 'error')
        return redirect(url_for('views.login'))  # Redirect back to login on error

# Route to handle file uploads from the frontend
@views.route('/upload_file', methods=['POST'])
def upload_file():
    email = session.get('email')
    auth = session.get('auth')

    if not email:
        return jsonify({"error": "User is not logged in"}), 403

    # Retrieve file data from request.json (as it's coming from the frontend as JSON)
    data = request.json
    filename = data.get('filename')
    file_content = data.get('content')

    # Debugging logs to verify data is being correctly received
    print(f"Email: {email}, Auth: {auth}, Filename: {filename}")

    if not filename or not file_content:
        return jsonify({"error": "Missing required fields"}), 400

    # Choose RSA key size based on auth (1 for 2048, else 1024)
    key_size = 2048 if auth == 1 else 1024
    encryption_method = "RSA"

    # Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair(key_size)

    # Encrypt the file content using RSA public key
    encrypted_content = rsa_encrypt(public_key, file_content)

    # Serialize the public key to send to the backend along with the encrypted content
    public_key_serialized = serialize_public_key(public_key)
    print("encrypted file content is :",encrypted_content)
    # Send the encrypted data and other details to the backend (running on port 8000)
    try:
        response = requests.post('http://localhost:8000/api/upload_file', json={
            "email": email,
            "filename": filename,
            "content": encrypted_content.hex(),  # Send as hex for easy JSON transmission
            "public_key": public_key_serialized.decode('utf-8'),  # Send public key as a string
            "encryption_method": encryption_method,
            "key_size": key_size
        })

        if response.status_code == 200:
            return jsonify({"message": f"File uploaded successfully with RSA encryption (key size: {key_size})"}), 200
        else:
            error_data = response.json()
            return jsonify({"error": error_data.get("error", "Failed to upload the file")}), response.status_code

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to connect to the backend: {str(e)}"}), 500