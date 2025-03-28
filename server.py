from flask import Flask, render_template, request, send_file, jsonify, session
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import base64
import os
import io
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Global variables for keys
private_key = None
public_key = None
private_key_path = 'private_key.pem'
public_key_path = 'public_key.pem'
last_generated_hash = None  # Per tenere traccia dell'ultimo hash generato

def get_keys():
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        with open(private_key_path, 'rb') as private_file:
            private_key = serialization.load_pem_private_key(
                private_file.read(),
                password=None
            )
        with open(public_key_path, 'rb') as public_file:
            public_key = serialization.load_pem_public_key(public_file.read())
        return private_key, public_key
    else:
        raise FileNotFoundError("Le chiavi non sono state trovate.")

@app.route('/', methods=['GET'])
def index():
    key_status = {
        "private_key_exists": os.path.exists(private_key_path),
        "public_key_exists": os.path.exists(public_key_path)
    }
    return render_template('index.html', key_status=key_status)

@app.route('/download_signature', methods=['POST'])
def download_signature():
    signature = request.form.get('signature', '')
    original_text = request.form.get('original_text', '')
    hash_value = request.form.get('hash_value', '')
    
    if not signature:
        return "Nessuna firma da scaricare", 400
    
    # Crea un file con il testo originale, hash e firma
    content = f"Testo originale: {original_text}\n\nHash SHA-256: {hash_value}\n\nFirma digitale: {signature}"
    
    # Crea un oggetto file-like in memoria
    buffer = io.BytesIO()
    buffer.write(content.encode('utf-8'))
    buffer.seek(0)
    
    # Invia il file come allegato
    return send_file(
        buffer,
        as_attachment=True,
        download_name="firma_digitale.txt",
        mimetype="text/plain"
    )

@app.route('/sign', methods=['POST'])
def sign_text():
    global last_generated_hash
    original_text = request.form.get('text', '')
    
    # Crea hash SHA-256 del testo
    digest = hashes.Hash(hashes.SHA256())
    digest.update(original_text.encode())
    hash_value = digest.finalize().hex()
    
    # Salva l'hash per confronti futuri
    last_generated_hash = hash_value
    
    # Firma il digest con la chiave privata
    try:
        signature_bytes = private_key.sign(
            hash_value.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signature = base64.b64encode(signature_bytes).decode()
        return jsonify({
            'success': True,
            'original_text': original_text,
            'hash_value': hash_value,
            'signature': signature
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/verify', methods=['POST'])
def verify_signature():
    global last_generated_hash
    
    if 'signature_file' not in request.files:
        return jsonify({'success': False, 'error': 'Nessun file caricato'})
        
    file = request.files['signature_file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Nome file non valido'})
    
    # Leggi contenuto del file
    content = file.read().decode('utf-8')
    
    # Estrai testo, hash e firma
    original_text_match = re.search(r"Testo originale: (.*?)(?:\n|$)", content)
    signature_match = re.search(r"Firma digitale: (.*?)(?:\n|$)", content)
    hash_match_regex = re.search(r"Hash SHA-256: (.*?)(?:\n|$)", content)
    
    if not (original_text_match and signature_match and hash_match_regex):
        return jsonify({'success': False, 'error': 'Formato file non valido'})
    
    upload_text = original_text_match.group(1)
    upload_signature = signature_match.group(1)
    saved_hash = hash_match_regex.group(1)
    
    # Calcola hash del testo
    digest = hashes.Hash(hashes.SHA256())
    digest.update(upload_text.encode())
    upload_hash = digest.finalize().hex()
    
    # Controlla hash con quello salvato nel file
    hash_match_file = saved_hash == upload_hash
    
    # Controlla se l'hash corrisponde all'ultimo hash generato
    hash_match_last_generated = last_generated_hash == saved_hash if last_generated_hash else None
    
    # Verifica la firma crittografica
    try:
        public_key.verify(
            base64.b64decode(upload_signature),
            saved_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        crypto_verification = True
    except InvalidSignature:
        crypto_verification = False
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f"Errore durante la verifica: {str(e)}"
        })
    
    # Determina il risultato complessivo di autenticità
    if not crypto_verification:
        verification_result = False
        result_message = "Firma non autentica: la firma non è stata creata con la chiave privata corrispondente"
    elif not hash_match_file:
        verification_result = False
        result_message = "Firma non autentica: il contenuto del documento è stato alterato"
    elif hash_match_last_generated is False:
        verification_result = False
        result_message = "Firma non autentica: non corrisponde all'ultimo documento firmato"
    elif hash_match_last_generated:
        verification_result = True
        result_message = "Firma autentica: corrisponde esattamente all'ultimo documento firmato"
    else:
        verification_result = True
        result_message = "Firma autentica: il documento non è stato alterato"
    
    return jsonify({
        'success': True,
        'original_text': upload_text,
        'upload_hash': upload_hash,
        'saved_hash': saved_hash, 
        'last_generated_hash': last_generated_hash,
        'upload_signature': upload_signature,
        'verification_result': verification_result,
        'hash_match_file': hash_match_file,
        'hash_match_last_generated': hash_match_last_generated,
        'result_message': result_message
    })

if __name__ == '__main__':
    private_key, public_key = get_keys()
    app.run(debug=True, port=56000)