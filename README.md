# Código-fonte do PDV — versão 1.0.6

Este pacote corresponde à aplicação incluída no instalador do Empório D&D PDV enviado em 1º de novembro de 2026. Inclui o backend FastAPI, a interface web, dependências e testes. Não inclui banco de dados, credenciais locais, arquivos `.env`, runtime Python ou o projeto NSIS do instalador.

## Arquivos principais

- `app.py`: API, autenticação, banco SQLite, vendas, Fiado, estoque e auditoria.
- `static/index.html`: interface do PDV.
- `backup.py` e `redefinir_senha_admin.py`: utilitários administrativos.
- `requirements.txt`: dependências de execução fixadas para Python 3.8.
- `tests/test_flows.py`: testes de integração.

## Executar para desenvolvimento

Use Python 3.8 ou compatível. Na pasta extraída, crie um ambiente virtual, instale `requirements.txt` e execute:

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn app:APP --host 127.0.0.1 --port 8080
```

Abra `http://127.0.0.1:8080` no navegador. Sem `PDV_DATA_DIR`, a aplicação cria o banco em `data/pdv.sqlite3` junto ao código. Para executar os testes, instale também `requirements-dev.txt` e rode `python -m unittest discover -s tests -v`.

Para acesso de outros computadores, use somente uma rede privada confiável ou VPN; não exponha diretamente a porta do PDV à internet pública.
