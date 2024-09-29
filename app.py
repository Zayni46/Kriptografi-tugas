from flask import Flask, render_template, request, send_file
from ciphers import encrypt_vigenere, decrypt_vigenere, encrypt_playfair, decrypt_playfair, encrypt_hill, decrypt_hill, encrypt_super, decrypt_super
import io

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        # Periksa apakah ada file yang diunggah
        uploaded_file = request.files.get('fileInput')
        
        if uploaded_file:
            # Jika file diunggah, bacalah isinya sebagai byte
            file_content = uploaded_file.read().decode('utf-8')  # Asumsi file teks, ubah jika file biner
            plaintext = file_content
        else:
            # Jika tidak ada file, ambil teks dari form
            plaintext = request.form['plaintext']
        
        key = request.form['key']
        cipher = request.form['cipher']
        
        # Proses enkripsi berdasarkan cipher yang dipilih
        if cipher == 'vigenere':
            ciphertext = encrypt_vigenere(plaintext, key)
        elif cipher == 'playfair':
            ciphertext = encrypt_playfair(plaintext, key)
        elif cipher == 'hill':
            ciphertext = encrypt_hill(plaintext, key)
        elif cipher == 'super':
            ciphertext = encrypt_super(plaintext, key)
        else:
            ciphertext = 'Cipher tidak dikenal'
        
        return render_template('index.html', result=ciphertext)
        
    except ValueError as e:
        return render_template('index.html', result=str(e))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        # Periksa apakah ada file yang diunggah
        uploaded_file = request.files.get('fileCipherInput')
        
        if uploaded_file:
            # Jika file diunggah, bacalah isinya sebagai byte
            file_content = uploaded_file.read().decode('utf-8')  # Asumsi file teks, ubah jika file biner
            ciphertext = file_content
        else:
            # Jika tidak ada file, ambil teks dari form
            ciphertext = request.form['ciphertext']
        
        key = request.form['key']
        cipher = request.form['cipher']
        
        # Proses dekripsi berdasarkan cipher yang dipilih
        if cipher == 'vigenere':
            plaintext = decrypt_vigenere(ciphertext, key)
        elif cipher == 'playfair':
            plaintext = decrypt_playfair(ciphertext, key)
        elif cipher == 'hill':
            plaintext = decrypt_hill(ciphertext, key)
        elif cipher == 'super':
            plaintext = decrypt_super(ciphertext, key)
        else:
            plaintext = 'Cipher tidak dikenal'
        
        return render_template('index.html', result=plaintext)
        
    except ValueError as e:
        return render_template('index.html', result=str(e))

# Menyediakan fungsi untuk menyimpan hasil enkripsi/dekripsi sebagai file untuk diunduh
@app.route('/download', methods=['POST'])
def download():
    try:
        # Hasil enkripsi atau dekripsi dari textarea
        content = request.form['result']
        # Simpan file sebagai biner
        return send_file(
            io.BytesIO(content.encode('utf-8')),
            as_attachment=True,
            download_name='result.txt',  # Bisa disesuaikan dengan ekstensi yang diinginkan
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return render_template('index.html', result=str(e))

if __name__ == '__main__':
    app.run(debug=True)
