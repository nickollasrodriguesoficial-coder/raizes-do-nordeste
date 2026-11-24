import hashlib
import secrets
import sqlite3
from getpass import getpass
from pathlib import Path

banco = Path(__file__).with_name("raizes.db")

perfil = input("Qual perfil deseja cadastrar (atendente ou gerente)? ").strip().lower()
if perfil not in ("atendente", "gerente"):
    raise SystemExit("Digite atendente ou gerente.")

senha = getpass("Escolha uma senha de teste com pelo menos 8 caracteres: ")
if len(senha) < 8:
    raise SystemExit("A senha precisa ter pelo menos 8 caracteres.")
if senha != getpass("Digite a senha novamente: "):
    raise SystemExit("As senhas ficaram diferentes. Execute o programa de novo.")

sal = secrets.token_bytes(16)
rodadas = 600_000
resumo = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), sal, rodadas)
senha_hash = f"pbkdf2_sha256${rodadas}${sal.hex()}${resumo.hex()}"

conexao = sqlite3.connect(banco)
try:
    with conexao:
        cadastro = conexao.execute(
            "INSERT INTO usuario (login, senha_hash, perfil) VALUES (?, ?, ?) "
            "ON CONFLICT(login) DO NOTHING",
            (perfil, senha_hash, perfil)
        )
    if cadastro.rowcount == 1:
        print(f"Usuário {perfil} cadastrado com sucesso.")
    else:
        print(f"O usuário {perfil} já está cadastrado.")
finally:
    conexao.close()