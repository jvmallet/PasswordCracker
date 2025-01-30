import hashlib
import bcrypt
import argon2
from tqdm import tqdm

def verificar_senha(hash_tipo, hash_val, senha):
    if hash_tipo == "MD5":
        return hashlib.md5(senha.encode()).hexdigest() == hash_val
    elif hash_tipo == "SHA-256":
        return hashlib.sha256(senha.encode()).hexdigest() == hash_val
    elif hash_tipo == "SHA-512":
        return hashlib.sha512(senha.encode()).hexdigest() == hash_val
    elif hash_tipo == "Bcrypt":
        return bcrypt.checkpw(senha.encode(), hash_val.encode())
    elif hash_tipo == "Argon2":
        try:
            argon2.PasswordHasher().verify(hash_val, senha)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
    return False

wordlist_path = "wordlists/common.txt"


with open(wordlist_path, "r", encoding="utf-8") as file:
        wordlist = file.read().splitlines()


hashes = []
hashes_path = "hashes/hashed_password.txt"

try:
    with open(hashes_path, "r", encoding="utf-8") as file:
        lines = [line.strip() for line in file.readlines() if line.strip()]  
        for i in range(0, len(lines), 6):  # Processa em blocos de 6 linhas
            if i + 5 >= len(lines):  # Evita erro de índice
                print(f" Erro: entrada incompleta na linha {i}, ignorando.")
                continue

            senha = lines[i].split(":", 1)[1].strip()
            hash_md5 = lines[i+1].split(":", 1)[1].strip()
            hash_sha256 = lines[i+2].split(":", 1)[1].strip()
            hash_sha512 = lines[i+3].split(":", 1)[1].strip()
            hash_bcrypt = lines[i+4].split(":", 1)[1].strip()
            hash_argon2 = lines[i+5].split(":", 1)[1].strip()

            hashes.append({
                "senha": senha,
                "MD5": hash_md5,
                "SHA-256": hash_sha256,
                "SHA-512": hash_sha512,
                "Bcrypt": hash_bcrypt,
                "Argon2": hash_argon2
            })
except FileNotFoundError:
    print(f"Erro: arquivo de hashes '{hashes_path}' não encontrado")
    exit()

# Executa ataque de dicionário
senhas_quebradas = set()

print("\n Iniciando ataque de dicionário")
for tentativa in tqdm(wordlist, desc="Testando senhas"):
    for hash_entry in hashes:
        senha_original = hash_entry["senha"]
        if senha_original in senhas_quebradas:
            continue  # Pula se a senha já foi quebrada
        
        for tipo, hash_val in hash_entry.items():
            if tipo != "senha" and verificar_senha(tipo, hash_val, tentativa):
                print(f"senha quebrada {tipo}: {tentativa}")
                senhas_quebradas.add(senha_original)

# 📌 Salvar os resultados em um arquivo
if senhas_quebradas:
    with open("senha_quebradas.txt", "w") as file:
        for senha in senhas_quebradas:
            file.write(f"{senha}\n")
    print("\n Resultados salvos em 'senha_quebradas.txt'")
else:
    print("\n Nenhuma senha foi quebrada.")
