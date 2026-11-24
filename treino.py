import hashlib
import hmac
import sqlite3 
import secrets
from pydantic import BaseModel, Field
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
app = FastAPI()
sessoes = {}
seguranca = HTTPBearer(auto_error=False)

def exigir_login(
    credencial: HTTPAuthorizationCredentials | None = Depends(seguranca)
):
    sessao = sessoes.get(credencial.credentials) if credencial else None
    if sessao is None:
        raise HTTPException(
            status_code=401,
            detail="Faça login para continuar",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return sessao
def exigir_gerente(sessao: dict = Depends(exigir_login)):
    if sessao["perfil"] != "gerente":
        raise HTTPException(status_code=403, detail="Acesso exclusivo do gerente")
    return sessao

class LoginEntrada(BaseModel):
    login: str
    senha: str
class ItemPedido(BaseModel):
    produto_codigo: int
    quantidade: int = Field(gt=0)
class PedidoEntrada(BaseModel):
    unidade_codigo: int
    canalPedido: str = Field(min_length=1)
    itens: list[ItemPedido] = Field(min_length=1)    
@app.get("/")
def inicio():
    return {"mensagem": "Olá, Amigo!"}

@app.get("/pedidos/{numero}")
def consultar_pedido(numero: int, sessao: dict = Depends(exigir_login)):
    conexao = sqlite3.connect("raizes.db")
    try:
        resultado = conexao.execute(
            "SELECT status FROM pedido WHERE numero = ?",
            (numero,)
        ).fetchone()

        if resultado is None:
            raise HTTPException(404, detail="Pedido não encontrado")

        conexao.execute(
            "INSERT INTO log_acesso (login, acao, pedido_numero) VALUES (?, ?, ?)",
            (sessao["login"], "consultar_pedido", numero)
        )
        conexao.commit()
        return {"numero": numero, "status": resultado[0]}
    finally:
        conexao.close()


@app.post("/pedidos/conferir")
def conferir_pedido(pedido: PedidoEntrada):
    quantidades = {}
    for item in pedido.itens:
        codigo = item.produto_codigo
        quantidades[codigo] = quantidades.get(codigo, 0) + item.quantidade

    conexao = sqlite3.connect("raizes.db")
    try:
        for codigo, pedida in quantidades.items():
            linha = conexao.execute(
                "SELECT quantidade FROM estoque "
                "WHERE unidade_codigo = ? AND produto_codigo = ?",
                (pedido.unidade_codigo, codigo)
            ).fetchone()

            disponivel = linha[0] if linha else 0
            if pedida > disponivel:
                raise HTTPException(
                    status_code=409,
                    detail=f"Estoque insuficiente para o produto {codigo}. "
                           f"Quantidade disponível: {disponivel}."
                )
    finally:
        conexao.close()

    return pedido

@app.post("/pedidos", status_code=201)
def criar_pedido(pedido: PedidoEntrada):
    conexao = sqlite3.connect("raizes.db")
    try:
        conexao.execute("PRAGMA foreign_keys = ON")
        with conexao:
            unidade = conexao.execute(
                "SELECT codigo FROM unidade WHERE codigo = ?",
                (pedido.unidade_codigo,)
            ).fetchone()
            if unidade is None:
                raise HTTPException(404, detail="Unidade não encontrada")

            novo = conexao.execute(
                "INSERT INTO pedido (unidade_codigo, canalPedido, estoque_reservado) VALUES (?, ?, 1)",
                (pedido.unidade_codigo, pedido.canalPedido)
            )
            numero = novo.lastrowid

            for item in pedido.itens:
                reserva = conexao.execute(
                    "UPDATE estoque SET quantidade = quantidade - ? "
                    "WHERE unidade_codigo = ? AND produto_codigo = ? "
                    "AND quantidade >= ?",
                    (item.quantidade, pedido.unidade_codigo,
                     item.produto_codigo, item.quantidade)
                )
                if reserva.rowcount == 0:
                    raise HTTPException(
                        409, detail=f"Estoque insuficiente para o produto {item.produto_codigo}."
                    )

                conexao.execute(
                    "INSERT INTO item_pedido (pedido_numero, produto_codigo, quantidade) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT (pedido_numero, produto_codigo) "
                    "DO UPDATE SET quantidade = quantidade + excluded.quantidade",
                    (numero, item.produto_codigo, item.quantidade)
                )
    finally:
        conexao.close()

    return {"numero": numero, "status": "Aguardando pagamento"}
@app.post("/pedidos/{numero}/pagamento/aprovar", dependencies=[Depends(exigir_gerente)])
def aprovar_pagamento(numero: int):
    conexao = sqlite3.connect("raizes.db")
    try:
        with conexao:
            alteracao = conexao.execute(
                "UPDATE pedido SET status = ? WHERE numero = ? AND status = ?",
                ("Pedido confirmado", numero, "Aguardando pagamento")
            )
            if alteracao.rowcount == 0:
                pedido = conexao.execute(
                    "SELECT status FROM pedido WHERE numero = ?", (numero,)
                ).fetchone()
                if pedido is None:
                    raise HTTPException(404, detail="Pedido não encontrado")
                raise HTTPException(409, detail="O pedido já saiu da etapa de pagamento")
    finally:
        conexao.close()

    return {"numero": numero, "status": "Pedido confirmado"}

@app.post("/pedidos/{numero}/pagamento/recusar")
def recusar_pagamento(numero: int):
    conexao = sqlite3.connect("raizes.db")
    try:
        with conexao:
            conexao.execute("BEGIN IMMEDIATE")
            pedido = conexao.execute(
                "SELECT unidade_codigo, status, estoque_reservado "
                "FROM pedido WHERE numero = ?",
                (numero,)
            ).fetchone()

            if pedido is None:
                raise HTTPException(404, detail="Pedido não encontrado")

            unidade, status, reservado = pedido
            if status != "Aguardando pagamento":
                raise HTTPException(409, detail="O pedido já saiu da etapa de pagamento")

            if reservado:
                itens = conexao.execute(
                    "SELECT produto_codigo, quantidade FROM item_pedido "
                    "WHERE pedido_numero = ?",
                    (numero,)
                ).fetchall()

                for produto, quantidade in itens:
                    conexao.execute(
                        "INSERT INTO estoque (unidade_codigo, produto_codigo, quantidade) "
                        "VALUES (?, ?, ?) "
                        "ON CONFLICT (unidade_codigo, produto_codigo) "
                        "DO UPDATE SET quantidade = estoque.quantidade + excluded.quantidade",
                        (unidade, produto, quantidade)
                    )

            conexao.execute(
                "UPDATE pedido SET status = 'Pagamento recusado', estoque_reservado = 0 "
                "WHERE numero = ?",
                (numero,)
            )
    finally:
        conexao.close()

    return {
        "numero": numero,
        "status": "Pagamento recusado",
        "mensagem": "Verifique a forma de pagamento."
    }

@app.post("/login")
def fazer_login(dados: LoginEntrada):
    conexao = sqlite3.connect("raizes.db")
    try:
        usuario = conexao.execute(
            "SELECT senha_hash, perfil FROM usuario WHERE login = ?",
            (dados.login,)
        ).fetchone()
    finally:
        conexao.close()

    if usuario is None:
        raise HTTPException(401, detail="Login ou senha inválidos")

    senha_hash, perfil = usuario
    algoritmo, rodadas, sal, esperado = senha_hash.split("$")
    if algoritmo != "pbkdf2_sha256":
        raise HTTPException(401, detail="Login ou senha inválidos")

    calculado = hashlib.pbkdf2_hmac(
        "sha256", dados.senha.encode("utf-8"), bytes.fromhex(sal), int(rodadas)
    )
    if not hmac.compare_digest(calculado.hex(), esperado):
        raise HTTPException(401, detail="Login ou senha inválidos")

    token = secrets.token_urlsafe(32)
    sessoes[token] = {"login": dados.login, "perfil": perfil}

    return {
        "login": dados.login,
        "perfil": perfil,
        "access_token": token,
        "token_type": "bearer"
    }

class ConsentimentoEntrada(BaseModel):
    decisao: str = Field(pattern="^(aceito|revogado)$")


@app.post("/consentimentos", status_code=201)
def registrar_consentimento(
    dados: ConsentimentoEntrada,
    sessao: dict = Depends(exigir_login)
):
    """Termo v1. Você autoriza o uso do seu login no relatório de demonstração
    acadêmica? Essa escolha é opcional. Envie 'aceito' para autorizar ou
    'revogado' para retirar a autorização. A escolha não afeta seus pedidos.
    """
    finalidade = "Uso do login no relatório de demonstração acadêmica"
    conexao = sqlite3.connect("raizes.db")
    try:
        usuario = conexao.execute(
            "SELECT codigo FROM usuario WHERE login = ?",
            (sessao["login"],)
        ).fetchone()
        if usuario is None:
            raise HTTPException(401, detail="Usuário da sessão não encontrado")

        conexao.execute(
            "INSERT INTO consentimento "
            "(usuario_codigo, finalidade, versao_termo, decisao) "
            "VALUES (?, ?, ?, ?)",
            (usuario[0], finalidade, "v1", dados.decisao)
        )
        conexao.commit()
    finally:
        conexao.close()

    return {"decisao": dados.decisao, "finalidade": finalidade, "versao_termo": "v1"}