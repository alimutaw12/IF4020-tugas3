from flask import Flask, render_template, jsonify, request, send_file, url_for
from cipher.cipher import *
import os
from datetime import datetime

app = Flask(__name__)

@app.route("/")
def main():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def routeEncrypt():
    plaintext = str.encode('Lorem ipsum dolor sit amet, consectetur adipiscing elit.')
    key = 'PdSgVkYp3s6v8y/B'
    IV = 'dRgUkXp2r5u8x/A?'
    result_ciphertext = encrypt(plaintext, key, IV=IV)

    filename = datetime.now().strftime("%d-%m-%Y %H.%M.%S") + '.txt'

    file = open(f'storage/{filename}', 'wb')
    file.write(result_ciphertext)
    
    data = { 
        "chipherText" : bytesToChar(result_ciphertext), 
        "key": key,
        "link": request.scheme + '://' + request.host + '/download/' + filename,
        "filename": filename
    } 

    return jsonify(data)

@app.route('/download/<filename>', methods=['GET'])
def download(filename):
    current_directory = os.getcwd() + '\storage'
    path = os.path.join(current_directory, filename)

    return send_file(path, as_attachment=True)

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    # Save the file and process the name as needed
    file.save('storage/' + file.filename)
    
    filename = file.filename
    ext = filename.split(".")[-1]
    file = open(f'storage/{filename}', 'rb')
    plaintext = file.read()

    key = 'PdSgVkYp3s6v8y/B'
    IV = 'dRgUkXp2r5u8x/A?'
    result_ciphertext = encrypt(plaintext, key, IV=IV)

    filename = datetime.now().strftime("%d-%m-%Y %H.%M.%S") + '.' + ext

    file = open(f'storage/{filename}', 'wb')
    file.write(result_ciphertext)
    
    data = {
        "link": request.scheme + '://' + request.host + '/download/' + filename,
        "filename": filename
    }
    
    return jsonify(data)

if __name__ == "__main__":
    app.run()