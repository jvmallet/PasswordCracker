import hashlib
import bcrypt
import argon2

def gera_hash(senha):
    
    hashes = {
        "MD5": hashlib.md5(senha.encode()).hexdigest(),
        "SHA-256": hashlib.sha256(senha.encode()).hexdigest(),
        "SHA-512": hashlib.sha512(senha.encode()).hexdigest(),
        "Bcrypt": bcrypt.hashpw(senha.encode(),bcrypt.gensalt()).decode(),
        "Argon2": argon2.PasswordHasher().hash(senha)
    }

    return hashes


# lista de senhas para testes
senhas_testes = ["password","123456", "admin", "letmein", "qwerty"]

# gerar e salvar os hashes em um arquivo
with open("hashes/hashed_password.txt","w") as file:
        for senha in senhas_testes:
            hashes = gera_hash (senha)
            file.write(f"Senha: {senha}\n")
            for tipo,hash_val in hashes.items():
                file.write(f"{tipo}:{hash_val}\n")
            file.write("\n")

print("Hashes gerados e salvos")


