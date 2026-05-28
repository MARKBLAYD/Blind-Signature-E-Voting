from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import json

# --- Генерация RSA ключей ---
def generate_rsa_key_pair(bits=2048):
    key = RSA.generate(bits)
    return bytes_to_psql_bytea(key.publickey().export_key(format='DER')), bytes_to_psql_bytea(key.export_key(format='DER'))  # BYTEA

# --- Создание метки M ---
def generate_m():
    return bytes_to_psql_bytea(get_random_bytes(32))  # 256-битная случайная строка

# --- Слепление M в Mbl: Mbl = M * r^e mod n ---
def blind_message(M: bytes, r: int, pub_key_der: bytes) -> bytes:
    pub_key = import_rsa_key(psql_bytea_to_bytes(pub_key_der))
    M_int = bytes_to_long(psql_bytea_to_bytes(M))
    Mbl = (M_int * pow(r, pub_key.e, pub_key.n)) % pub_key.n
    return bytes_to_psql_bytea(long_to_bytes(Mbl))

# --- Подпись слепой метки Mbl ---
def sign_message_blinded(priv_key_der: bytes, message_bytes: bytes) -> bytes:
    key = import_rsa_key(psql_bytea_to_bytes(priv_key_der))
    h = SHA256.new(psql_bytea_to_bytes(message_bytes))
    return bytes_to_psql_bytea(pkcs1_15.new(key).sign(h))

# --- Проверка подписи ---
def verify_signature(pub_key_der: bytes, signature: bytes, message_bytes: bytes) -> bool:
    key = import_rsa_key(psql_bytea_to_bytes(pub_key_der))
    h = SHA256.new(message_bytes)
    try:
        pkcs1_15.new(key).verify(h, psql_bytea_to_bytes(signature))
        return True
    except (ValueError, TypeError):
        return False

# --- Снятие слепоты подписи ---
def unblind_signature(blinded_signature: bytes, r: int, pub_key_der: bytes) -> bytes:
    key = import_rsa_key(psql_bytea_to_bytes(pub_key_der))
    r_inv = inverse(r, key.n)
    sig_int = bytes_to_long(psql_bytea_to_bytes(blinded_signature))
    return bytes_to_psql_bytea(long_to_bytes((sig_int * r_inv) % key.n))

# --- Шифрование бюллетеня ---
def encrypt_ballot(pub_key_der: bytes, M: bytes, DS: bytes, B: int) -> bytes:
    key = import_rsa_key(psql_bytea_to_bytes(pub_key_der))
    M=psql_bytea_to_bytes(M)
    DS=psql_bytea_to_bytes(DS)
    cipher = PKCS1_OAEP.new(key)
    ballot = json.dumps({
        "M": M.hex(),
        "DS": DS.hex(),
        "B": B
    }).encode()
    return cipher.encrypt(ballot)

# --- Расшифровка бюллетеня ---
def decrypt_ballot(priv_key_der: bytes, encrypted: bytes):

    key = import_rsa_key(psql_bytea_to_bytes(priv_key_der))
    cipher = PKCS1_OAEP.new(key)
    ballot = json.loads(cipher.decrypt(encrypted).decode())
    return {
        "M": bytes_to_psql_bytea(bytes.fromhex(ballot["M"])),
        "DS": bytes_to_psql_bytea(bytes.fromhex(ballot["DS"])),
        "B": ballot["B"]
    }

import psycopg2

def bytes_to_psql_bytea(data: bytes):
    """Готовит данные для вставки в поле BYTEA PostgreSQL."""
    return psycopg2.Binary(data)

def psql_bytea_to_bytes(bytea_field) -> bytes:
    """При извлечении BYTEA из базы он уже bytes, но эта функция — для ясности."""
    return bytes(bytea_field)