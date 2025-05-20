from flask import Flask, render_template, request, jsonify
from encryption import generate_key_from_password, fernet_encrypt, xor_encrypt, xor_decrypt, fernet_decrypt

app = Flask(__name__)

@app.route('/')

def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])

def encrypt():
    data = request.json
    password = data['password']
    text = data['text']
    key = generate_key_from_password(password)
    encrypted = fernet_encrypt(text, key)
    xor_encrypted = xor_encrypt(encrypted, key)
    return jsonify({'result': xor_encrypted}) # returns it as json

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    password = data['password']
    encrypted = data['text']
    key = generate_key_from_password(password)
    try:
        decrypted_fernet = xor_decrypt(encrypted, key)
        decrypted = fernet_decrypt(decrypted_fernet, key)
        return jsonify({'result': decrypted})
    except Exception:
        return jsonify({'error': 'Wrong key or corrupted data.'}), 400

if __name__ == '__main__':
    app.run(debug=True)