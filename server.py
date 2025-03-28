from flask import Flask, render_template, request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import base64
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Percorsi dei file per le chiavi
private_key_path = "private_key.pem"
public_key_path = "public_key.pem"

# Genera o carica le chiavi
def get_keys():
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        # Carica chiavi esistenti
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
    else:
        # Genera nuove chiavi
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Salva la chiave privata
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Salva la chiave pubblica
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    return private_key, public_key

# Ottieni le chiavi all'avvio dell'applicazione
private_key, public_key = get_keys()

@app.route('/', methods=['GET', 'POST'])
def index():
    hash_value = ''
    signature = ''
    verification_result = None
    original_text = ''
    verification_details = ''
    
    if request.method == 'POST':
        original_text = request.form.get('text', '')
        
        # Crea hash SHA-256 del testo (irreversibile)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(original_text.encode())
        hash_value = digest.finalize().hex()
        
        # Firma il digest (hash) con la chiave privata
        signature_bytes = private_key.sign(
            hash_value.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signature = base64.b64encode(signature_bytes).decode()
        
        # Verifica della firma (mostrando dettagli del processo)
        try:
            # L'algoritmo di verifica controlla:
            # 1. Decodifica la firma con la chiave pubblica
            # 2. Estrae l'hash originale dalla firma
            # 3. Confronta l'hash estratto con l'hash del messaggio
            
            # Per simulare il risultato del processo, usiamo l'hash originale
            # (questo NON è ciò che realmente accade internamente, ma è utile per scopi didattici)
            verification_details = hash_value
            
            # Esegue la verifica effettiva
            public_key.verify(
                base64.b64decode(signature),
                hash_value.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            verification_result = True
        except InvalidSignature:
            verification_result = False
            verification_details = "La verifica della firma ha fallito"
    
    return render_template('index.html', 
                          original_text=original_text,
                          hash_value=hash_value,
                          signature=signature,
                          verification_result=verification_result,
                          verification_details=verification_details)

@app.route('/reload_keys', methods=['GET'])
def reload_keys():
    global private_key, public_key
    private_key, public_key = get_keys()
    return "Chiavi ricaricate. Chiave pubblica: " + public_key_path

@app.route('/key_info', methods=['GET'])
def key_info():
    key_status = {
        "private_key_file_exists": os.path.exists(private_key_path),
        "public_key_file_exists": os.path.exists(public_key_path),
        "keys_loaded_in_memory": private_key is not None and public_key is not None
    }
    return render_template('key_info.html', key_status=key_status)

if __name__ == '__main__':
    app.run(debug=True, port=56000)