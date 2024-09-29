def clean_key(key):
    """Fungsi untuk tidak membersihkan karakter non-alfabet agar kunci bisa berisi angka dan simbol."""
    return key  # Biarkan kunci apa adanya, tanpa menghapus angka/simbol

def encrypt_vigenere(plaintext, key):
    allowed_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    key = clean_key(key)  # Bersihkan key agar hanya mengandung huruf
    if len(key) == 0:
        raise ValueError("Key tidak boleh kosong.")
    
    plaintext = plaintext.upper().replace(" ", "")
    ciphertext = ''

    key_length = len(key)
    key_as_int = [allowed_chars.index(k) for k in key]  # Hitung indeks berdasarkan allowed_chars
    plaintext_int = [allowed_chars.index(p) for p in plaintext if p in allowed_chars]

    for i in range(len(plaintext_int)):
        value = (plaintext_int[i] + key_as_int[i % key_length]) % len(allowed_chars)
        ciphertext += allowed_chars[value]

    return ciphertext.lower()

def decrypt_vigenere(ciphertext, key):
    allowed_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    key = clean_key(key)  # Bersihkan key agar hanya mengandung huruf
    if len(key) == 0:
        raise ValueError("Key tidak boleh kosong.")
    
    ciphertext = ciphertext.upper().replace(" ", "")
    plaintext = ''

    key_length = len(key)
    key_as_int = [allowed_chars.index(k) for k in key]
    ciphertext_int = [allowed_chars.index(c) for c in ciphertext if c in allowed_chars]

    for i in range(len(ciphertext_int)):
        value = (ciphertext_int[i] - key_as_int[i % key_length]) % len(allowed_chars)
        plaintext += allowed_chars[value]

    return plaintext.lower()

# Playfair Cipher
def generate_playfair_matrix(key):
    key = key.upper().replace("J", "I")  # Ganti J dengan I
    allowed_chars = "ABCDEFGHIKLMNOPQRSTUVWXYZ0123456789"
    matrix = []
    used_chars = set()

    # Membuat matriks 5x5 berdasarkan key
    for char in key:
        if char not in used_chars and char in allowed_chars:
            matrix.append(char)
            used_chars.add(char)

    for char in allowed_chars:
        if char not in used_chars:
            matrix.append(char)

    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def playfair_encrypt_pair(a, b, matrix):
    # Implementasi enkripsi Playfair untuk setiap pasang huruf
    row1, col1 = divmod(matrix.index(a), 5)
    row2, col2 = divmod(matrix.index(b), 5)

    if row1 == row2:
        return matrix[row1 * 5 + (col1 + 1) % 5], matrix[row2 * 5 + (col2 + 1) % 5]
    elif col1 == col2:
        return matrix[((row1 + 1) % 5) * 5 + col1], matrix[((row2 + 1) % 5) * 5 + col2]
    else:
        return matrix[row1 * 5 + col2], matrix[row2 * 5 + col1]

def encrypt_playfair(plaintext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = plaintext.upper().replace("J", "I").replace(" ", "")

    if len(plaintext) % 2 != 0:
        plaintext += 'X'  # Tambahkan padding jika perlu

    ciphertext = ""
    for i in range(0, len(plaintext), 2):
        a, b = plaintext[i], plaintext[i + 1]
        ciphertext += ''.join(playfair_encrypt_pair(a, b, ''.join(sum(matrix, []))))

    return ciphertext

def playfair_decrypt_pair(a, b, matrix):
    row1, col1 = divmod(matrix.index(a), 5)
    row2, col2 = divmod(matrix.index(b), 5)

    if row1 == row2:
        return matrix[row1 * 5 + (col1 - 1) % 5], matrix[row2 * 5 + (col2 - 1) % 5]
    elif col1 == col2:
        return matrix[((row1 - 1) % 5) * 5 + col1], matrix[((row2 - 1) % 5) * 5 + col2]
    else:
        return matrix[row1 * 5 + col2], matrix[row2 * 5 + col1]

def decrypt_playfair(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    flat_matrix = ''.join(sum(matrix, []))  # Rata-rata matriks menjadi satu string
    ciphertext = ciphertext.upper().replace(" ", "")

    # Tambahkan padding jika panjang ganjil
    if len(ciphertext) % 2 != 0:
        ciphertext += 'X'  # Menambahkan padding jika perlu

    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        
        # Cek apakah karakter ada dalam matriks
        if a not in flat_matrix or b not in flat_matrix:
            raise ValueError(f"Character '{a}' or '{b}' not found in the matrix.")

        plaintext += ''.join(playfair_decrypt_pair(a, b, flat_matrix))

    return plaintext

# Hill Cipher
import numpy as np

def hill_matrix_key(key):
    matrix = []
    key = key.upper()
    for char in key:
        matrix.append(ord(char) - ord('A'))
    matrix = np.array(matrix).reshape(2, 2)  # Matriks 2x2 sebagai contoh
    return matrix

def encrypt_hill(plaintext, key):
    key_matrix = hill_matrix_key(key)
    plaintext = plaintext.upper().replace(" ", "")
    if len(plaintext) % 2 != 0:
        plaintext += 'X'  # Tambahkan padding jika perlu

    ciphertext = ''
    for i in range(0, len(plaintext), 2):
        vec = np.array([ord(plaintext[i]) - ord('A'), ord(plaintext[i + 1]) - ord('A')])
        result = np.dot(key_matrix, vec) % 26
        ciphertext += chr(result[0] + ord('A')) + chr(result[1] + ord('A'))

    return ciphertext

def decrypt_hill(ciphertext, key):
    key_matrix = hill_matrix_key(key)
    det = int(np.round(np.linalg.det(key_matrix))) % 26
    inv_det = pow(det, -1, 26)  # Invers modulo 26
    inv_key_matrix = np.round(inv_det * np.linalg.inv(key_matrix)).astype(int) % 26  # Membalikkan matriks kunci
    
    plaintext = ''
    for i in range(0, len(ciphertext), 2):
        vec = np.array([ord(ciphertext[i]) - ord('A'), ord(ciphertext[i + 1]) - ord('A')])
        result = np.dot(inv_key_matrix, vec) % 26
        plaintext += chr(result[0] + ord('A')) + chr(result[1] + ord('A'))

    return plaintext

# Super Encryption (Vigenere + Transposisi Kolom)
def transpose_columnar(plaintext, key):
    n = len(key)
    columns = [''] * n
    for i, char in enumerate(plaintext):
        columns[i % n] += char
    return ''.join(columns)

def encrypt_super(plaintext, key):
    vigenere_encrypted = encrypt_vigenere(plaintext, key)  # Enkripsi dengan Vigenere Cipher
    return transpose_columnar(vigenere_encrypted, key)     # Transposisi kolom

def decrypt_super(ciphertext, key):
    n = len(key)
    # Proses invers transposisi kolom
    col_length = len(ciphertext) // n + (1 if len(ciphertext) % n != 0 else 0)
    columns = [''] * n
    
    for i in range(n):
        columns[i] = ciphertext[i * col_length: (i + 1) * col_length]
    
    plaintext = ''
    for i in range(col_length):
        for j in range(n):
            if i < len(columns[j]):
                plaintext += columns[j][i]

    # Sekarang dekripsi hasil Vigenere
    return decrypt_vigenere(plaintext, key)

