import logging
from typing import Union
from fastapi import Request, Form
import jinja2
import requests
from cryptography.exceptions import InvalidSignature
from fastapi import FastAPI, HTTPException
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import base64
import paramiko
import binascii
from cryptography.fernet import Fernet
import secrets
app = FastAPI()
templates = Jinja2Templates(directory="./templates")

# Global variables to store keys
symmetric_key = None
public_key_rsa = None
private_key_rsa = None

# @app.get("/", response_class=HTMLResponse)
# async def index(request: Request):
#     return templates.TemplateResponse("index.html", {"request": request})

# Symmetric encryption routes
@app.get("/symmetric/key", tags=["symmetric-key"])
def generate_symmetric_key():
    global symmetric_key
    symmetric_key = Fernet.generate_key()
    return {"key": symmetric_key.hex()}


@app.post("/symmetric/key", tags=["symmetric-key"])
def set_symmetric_key(key: str):
    global symmetric_key
    symmetric_key = bytes.fromhex(key)
    return {"message": "Symmetric key set successfully"}


@app.post("/symmetric/encode", tags=["symmetric-word"],)
def encode_message(message: str):
    if symmetric_key is None:
        raise HTTPException(status_code=400, detail="Symmetric key not set")
    cipher = Fernet(symmetric_key)
    encrypted_message = cipher.encrypt(message.encode())
    return {"encrypted_message": encrypted_message.hex()}


@app.post("/symmetric/decode", tags=["symmetric-word"])
def decode_message(encrypted_message: str):
    if symmetric_key is None:
        raise HTTPException(status_code=400, detail="Symmetric key not set")
    cipher = Fernet(symmetric_key)
    try:
        decrypted_message = cipher.decrypt(bytes.fromhex(encrypted_message)).decode()
        return {"decrypted_message": decrypted_message}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Decryption failed")


# Asymmetric encryption routes
@app.get("/asymmetric/key", tags=["asymmetric-key"])
def generate_asymmetric_key():
    global public_key_rsa, private_key_rsa
    private_key_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key_rsa = private_key_rsa.public_key()

    public_hex = public_key_rsa.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).hex()
    private_hex = private_key_rsa.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()
    return {"public_key": public_hex, "private_key": private_hex}


@app.get("/asymmetric/key/ssh", tags=["asymmetric-key"])
def get_ssh_key():
    global public_key_rsa, private_key_rsa
    if public_key_rsa is None or private_key_rsa is None:
        raise HTTPException(status_code=400, detail="Asymmetric keys not generated")

    ssh_public_key = public_key_rsa.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode()

    private_pem = private_key_rsa.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    ssh_private_key = private_pem.decode()

    return {
        "public_key_ssh": ssh_public_key,
        "private_key_ssh": ssh_private_key
    }


@app.post("/asymmetric/key", tags=["asymmetric-ssh"])
async def set_asymmetric_key(keys: dict):
    global public_key_rsa, private_key_rsa
    public_hex = keys.get("public_key")
    private_hex = keys.get("private_key")
    if not public_hex or not private_hex:
        raise HTTPException(status_code=400, detail="Both public_key and private_key are required")
    # Set public and private keys
    try:
        public_bytes = binascii.unhexlify(public_hex)
        private_bytes = binascii.unhexlify(private_hex)
        public_key_rsa = serialization.load_der_public_key(public_bytes)
        private_key_rsa = serialization.load_pem_private_key(private_bytes, password=None)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid key format")
    return {"message": "Keys set successfully"}


@app.post("/asymmetric/sign", tags=["asymmetric-word"])
async def sign_message(message: str):
    global private_key_rsa
    if not private_key_rsa:
        raise HTTPException(status_code=400, detail="Private key is not set")
    signature = private_key_rsa.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature = binascii.hexlify(signature).decode()
    return {"signature": signature}


@app.post("/asymmetric/verify", tags=["asymmetric-word"])
async def verify_message(message: str, signature: str):
    global public_key_rsa
    if not public_key_rsa:
        raise HTTPException(status_code=400, detail="Public key is not set")
    try:
        signature_bytes = binascii.unhexlify(signature)
        public_key_rsa.verify(
            signature_bytes,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        is_valid = True
    except InvalidSignature:
        is_valid = False
    return {"is_valid": is_valid}



@app.post("/asymmetric/encrypt", tags=["asymmetric-word_en/de"])
async def encrypt_message(message: str):
    global public_key_rsa
    if not public_key_rsa:
        raise HTTPException(status_code=400, detail="Public key is not set")
    ciphertext = public_key_rsa.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    ciphertext = binascii.hexlify(ciphertext).decode()
    return {"ciphertext": ciphertext}


@app.post("/asymmetric/decrypt", tags=["asymmetric-word_en/de"])
async def decrypt_message(ciphertext: str):
    global private_key_rsa
    if not private_key_rsa:
        raise HTTPException(status_code=400, detail="Private key is not set")
    plaintext = private_key_rsa.decrypt(
        binascii.unhexlify(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    plaintext = plaintext.decode()
    return {"plaintext": plaintext}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

