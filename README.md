# 🔐 Password Cracker - Educational Edition


## 📌 **Descrição**
Este é um **Password Cracker** projetado para demonstrar **como senhas fracas podem ser facilmente quebradas usando técnicas de ataque de dicionário**. O objetivo é educar sobre a **importância do uso de senhas seguras** e **hashing robusto** para armazenar credenciais.

## 🛠 **Recursos e Funcionalidades**
✔️ Ataque de **Dicionário** contra hashes MD5, SHA-256, SHA-512, Bcrypt e Argon2.  
✔️ **Otimizado** para evitar repetições e melhorar a eficiência.  
✔️ **Compatível com grandes wordlists** como `rockyou.txt`.  
✔️ Suporte para salvar senhas quebradas em um arquivo (`senha_quebradas.txt`).  
✔️ **Progresso visual** utilizando `tqdm`.

## 📂 **Estrutura do Projeto**
```
PasswordCracker/
│── venv/                    # Ambiente virtual
│── wordlists/                # Pasta para wordlists
│   ├── common.txt            # Lista de senhas comuns
│── hashes/                   # Pasta para armazenar hashes
│   ├── hashed_password.txt   # Arquivo de hashes das senhas
│── password_cracker.py       # Script principal
│── hash_generator.py         # Script para gerar hashes
│── requirements.txt          # Dependências do projeto
│── README.md                 # Documentação
```

## ⚙️ **Instalação e Configuração**
### **1️⃣ Clone o repositório**
```bash
git clone https://github.com/jvmallet/PasswordCracker.git
cd PasswordCracker
```

### **2️⃣ Crie um ambiente virtual e instale as dependências**
```bash
python3 -m venv venv
source venv/bin/activate  # No macOS/Linux
# No Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### **3️⃣ Crie ou edite a wordlist**
Abra `wordlists/common.txt` e adicione senhas fracas:
```txt
password
123456
admin
letmein
qwerty
iloveyou
```

### **4️⃣ Certifique-se de que o arquivo de hashes está formatado corretamente**
O arquivo `hashed_password.txt` deve conter senhas e seus respectivos hashes, assim:
```
Senha: password
MD5:5f4dcc3b5aa765d61d8327deb882cf99
SHA-256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
SHA-512:b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb98
Bcrypt:$2b$12$XpUHMY6AG8KHle2n0Wrwr.jmpVLDZUI7VPBF8Y8/OCEWDvvu5sp7O
Argon2:$argon2id$v=19$m=65536,t=3,p=4$lDvP92DKJpiH9S7o41IdpA$+NISK7siWncaAkKHzyUrWovW8tzmr5xhjf9mba4eqFg
```

### **5️⃣ Execute o ataque de dicionário**
```bash
python3 password_cracker.py
```

Se senhas forem quebradas, elas serão salvas em `senha_quebradas.txt`.

## 📊 **Comparação de Velocidade dos Algoritmos de Hashing**
Cada algoritmo de hash tem uma velocidade diferente para computação e verificação:
- **MD5 e SHA-256** são mais rápidos, mas menos seguros.
- **SHA-512** é mais seguro que SHA-256, mas um pouco mais lento.
- **Bcrypt e Argon2** são projetados para serem **intencionalmente lentos**, tornando o cracking mais difícil.

| Algoritmo | Tempo de Cálculo (aprox.) | Segurança |
|-----------|--------------------------|-----------|
| **MD5**   | Muito rápido (~0.00001s)  | Fraco ⚠️ |
| **SHA-256** | Rápido (~0.0001s)       | Médio 🟡 |
| **SHA-512** | Moderado (~0.0002s)     | Forte 🟢 |
| **Bcrypt**  | Lento (~0.1s)           | Muito Forte 🔒 |
| **Argon2**  | Muito Lento (~0.2s)     | Muito Forte 🔒 |

## 🚀 **Próximos Passos e Melhorias**
🔹 **Implementar multithreading para acelerar a execução.**  
🔹 **Adicionar suporte a ataques de mutação (ex: substituir "o" por "0").**  
🔹 **Usar GPU para aumentar a velocidade do cracking.**  
🔹 **Criar uma interface gráfica para visualizar o progresso.**  
🔹 **Testar com mais diferentes tipos de criptografia.**  

---
📌 **Criado por:** (https://github.com/jvmallet)  


