from __future__ import annotations
import csv, hashlib, hmac, io, json, os, re, secrets, sqlite3, time, threading, logging, unicodedata
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Header, Request, Response
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / '.env'
if ENV_FILE.exists():
    for line in ENV_FILE.read_text(encoding='utf-8').splitlines():
        line=line.strip()
        if not line or line.startswith('#') or '=' not in line: continue
        key,value=line.split('=',1); key=key.strip(); value=value.strip().strip('"').strip("'")
        if key and key not in os.environ: os.environ[key]=value
DATA_DIR = Path(os.getenv('PDV_DATA_DIR', ROOT / 'data'))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB = DATA_DIR / 'pdv.sqlite3'
APP = FastAPI(title='PDV Local', version='1.0.6')

SCHEMA = '''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('administrador','caixa','estoquista')), password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, barcode TEXT UNIQUE, sku TEXT UNIQUE NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', category_id INTEGER REFERENCES categories(id), unit TEXT NOT NULL DEFAULT 'unidade', cost_cents INTEGER NOT NULL DEFAULT 0, price_cents INTEGER NOT NULL DEFAULT 0, stock REAL NOT NULL DEFAULT 0, min_stock REAL NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_products_name ON products(name);
CREATE TABLE IF NOT EXISTS sales(id INTEGER PRIMARY KEY, number TEXT UNIQUE NOT NULL, operator_id INTEGER NOT NULL REFERENCES users(id), status TEXT NOT NULL CHECK(status IN ('concluida','cancelada')), subtotal_cents INTEGER NOT NULL, discount_cents INTEGER NOT NULL, total_cents INTEGER NOT NULL, idempotency_key TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, canceled_at TEXT, canceled_by INTEGER REFERENCES users(id), cancel_reason TEXT);
CREATE TABLE IF NOT EXISTS sale_items(id INTEGER PRIMARY KEY, sale_id INTEGER NOT NULL REFERENCES sales(id), product_id INTEGER NOT NULL REFERENCES products(id), sku TEXT NOT NULL, product_name TEXT NOT NULL, quantity REAL NOT NULL, unit_price_cents INTEGER NOT NULL, subtotal_cents INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY, sale_id INTEGER NOT NULL REFERENCES sales(id), method TEXT NOT NULL, amount_cents INTEGER NOT NULL, details TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'confirmado', provider TEXT, provider_ref TEXT, checkout_url TEXT);
CREATE TABLE IF NOT EXISTS credit_entries(id INTEGER PRIMARY KEY, sale_id INTEGER NOT NULL UNIQUE REFERENCES sales(id), customer_name TEXT NOT NULL, customer_key TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0), created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_credit_customer ON credit_entries(customer_key, created_at);
CREATE TABLE IF NOT EXISTS credit_customers(customer_key TEXT PRIMARY KEY, name TEXT NOT NULL, reference TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, created_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS stock_movements(id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id), user_id INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL, quantity REAL NOT NULL, balance_after REAL NOT NULL, reason TEXT NOT NULL, ref_type TEXT, ref_id INTEGER, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_movements_date ON stock_movements(created_at);
CREATE TABLE IF NOT EXISTS cash_sessions(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), opening_cents INTEGER NOT NULL, opened_at TEXT NOT NULL, closing_cents INTEGER, expected_cents INTEGER, difference_cents INTEGER, closed_at TEXT, status TEXT NOT NULL DEFAULT 'aberto');
CREATE TABLE IF NOT EXISTS cash_movements(id INTEGER PRIMARY KEY, cash_session_id INTEGER NOT NULL REFERENCES cash_sessions(id), user_id INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL, amount_cents INTEGER NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS credit_settlements(id INTEGER PRIMARY KEY, customer_key TEXT NOT NULL REFERENCES credit_customers(customer_key), amount_cents INTEGER NOT NULL CHECK(amount_cents>0), method TEXT NOT NULL, status TEXT NOT NULL, provider TEXT, provider_ref TEXT, external_reference TEXT UNIQUE NOT NULL, checkout_url TEXT, operator_id INTEGER NOT NULL REFERENCES users(id), cash_session_id INTEGER NOT NULL REFERENCES cash_sessions(id), idempotency_key TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, confirmed_at TEXT);
CREATE INDEX IF NOT EXISTS idx_credit_settlements_customer ON credit_settlements(customer_key, status, created_at);
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), action TEXT NOT NULL, entity TEXT NOT NULL, entity_id TEXT, details TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, actor_name TEXT NOT NULL DEFAULT '', actor_username TEXT NOT NULL DEFAULT '', before_json TEXT, after_json TEXT);
'''

def now(): return datetime.now().astimezone().isoformat(timespec='seconds')
def number(value):
    text=str(value).strip().replace(' ','')
    if ',' in text: text=text.replace('.','').replace(',','.')
    try: return float(text or 0)
    except ValueError: raise HTTPException(400,'Quantidade inválida no arquivo CSV.')
def money(value) -> int:
    text=str(value).strip().replace('R$','').replace(' ','')
    if ',' in text: text=text.replace('.','').replace(',','.')
    try: return int((Decimal(text).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP) * 100))
    except (InvalidOperation, ValueError): raise HTTPException(400, 'Valor monetário inválido.')
def customer_search_key(value):
    folded=unicodedata.normalize('NFKD',' '.join(str(value or '').split()).casefold())
    return ''.join(ch for ch in folded if not unicodedata.combining(ch))
def normalized_customer(value):
    name=' '.join(str(value or '').split())
    if not name or len(name)>120: raise HTTPException(400,'Informe o nome do cliente (até 120 caracteres) para registrar fiado.')
    key=hashlib.sha256(customer_search_key(name).encode('utf-8')).hexdigest()
    return name,key

def connect():
    c=sqlite3.connect(DB, timeout=20, isolation_level=None)
    c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.execute('PRAGMA busy_timeout=20000')
    return c
@contextmanager
def transaction(immediate=True):
    c=connect()
    try:
        c.execute('BEGIN IMMEDIATE' if immediate else 'BEGIN')
        yield c
        c.commit()
    except Exception:
        c.rollback(); raise
    finally: c.close()
def audit(c, user_id, action, entity, entity_id=None, details='', before=None, after=None):
    actor=c.execute('SELECT name,username FROM users WHERE id=?',(user_id,)).fetchone() if user_id is not None else None
    actor_name=actor['name'] if actor else ('Sistema' if user_id is None else 'Usuário removido')
    actor_username=actor['username'] if actor else ''
    before_json=json.dumps(before,ensure_ascii=False,sort_keys=True) if before is not None else None
    after_json=json.dumps(after,ensure_ascii=False,sort_keys=True) if after is not None else None
    c.execute('INSERT INTO audit_logs(user_id,action,entity,entity_id,details,created_at,actor_name,actor_username,before_json,after_json) VALUES(?,?,?,?,?,?,?,?,?,?)',(user_id,action,entity,str(entity_id or ''),details,now(),actor_name,actor_username,before_json,after_json))
def pw_hash(password: str) -> str:
    salt=secrets.token_bytes(16); digest=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1)
    return salt.hex()+':'+digest.hex()
def pw_check(password, stored):
    try:
        salt_hex, digest_hex=stored.split(':',1)
        return hmac.compare_digest(hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt_hex),n=2**14,r=8,p=1).hex(),digest_hex)
    except Exception: return False
def init_db():
    with connect() as c:
        c.executescript('PRAGMA journal_mode=WAL;'+SCHEMA)
        # Migrações aditivas preservam o banco SQLite já utilizado pelo PDV.
        audit_columns={r['name'] for r in c.execute('PRAGMA table_info(audit_logs)')}
        for column,declaration in (('actor_name',"TEXT NOT NULL DEFAULT ''"),('actor_username',"TEXT NOT NULL DEFAULT ''"),('before_json','TEXT'),('after_json','TEXT')):
            if column not in audit_columns: c.execute(f'ALTER TABLE audit_logs ADD COLUMN {column} {declaration}')
        c.execute("INSERT OR IGNORE INTO credit_customers(customer_key,name,reference,created_at) SELECT customer_key,MIN(customer_name),'',MIN(created_at) FROM credit_entries GROUP BY customer_key")
        customer_columns={r['name'] for r in c.execute('PRAGMA table_info(credit_customers)')}
        if 'phone' not in customer_columns:
            c.execute("ALTER TABLE credit_customers ADD COLUMN phone TEXT NOT NULL DEFAULT ''")
        user_columns={r['name'] for r in c.execute('PRAGMA table_info(users)')}
        if 'must_change_password' not in user_columns:
            c.execute('ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0')
        payment_columns={r['name'] for r in c.execute('PRAGMA table_info(payments)')}
        for column, declaration in (
            ('status', "TEXT NOT NULL DEFAULT 'confirmado'"),
            ('provider', 'TEXT'),
            ('provider_ref', 'TEXT'),
            ('checkout_url', 'TEXT'),
        ):
            if column not in payment_columns:
                c.execute(f'ALTER TABLE payments ADD COLUMN {column} {declaration}')
        for cat in ('Mercearia','Bebidas','Higiene e limpeza','Outros','Depósito','Frios','Embutidos'):
            c.execute('INSERT OR IGNORE INTO categories(name) VALUES(?)',(cat,))
        if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            username=os.getenv('PDV_ADMIN_USER','admin')
            password=os.getenv('PDV_ADMIN_PASSWORD')
            if not password:
                password=secrets.token_urlsafe(12)
                cred=DATA_DIR/'credenciais-iniciais.txt'
                cred.write_text(f'Usuário administrador: {username}\nSenha temporária: {password}\nAltere a senha após o primeiro acesso.\n',encoding='utf-8')
                try: cred.chmod(0o600)
                except OSError: pass
                print(f'Credenciais iniciais gravadas em: {cred}')
            c.execute('INSERT INTO users(username,name,role,password_hash,created_at) VALUES(?,?,?,?,?)',(username,'Administrador','administrador',pw_hash(password),now()))
        stock_username=os.getenv('PDV_STOCK_USER','estoque').strip()
        if stock_username and not c.execute('SELECT 1 FROM users WHERE username=?',(stock_username,)).fetchone():
            stock_password=os.getenv('PDV_STOCK_PASSWORD')
            generated=not bool(stock_password)
            if generated:
                stock_password=secrets.token_urlsafe(14)
            c.execute('INSERT INTO users(username,name,role,password_hash,created_at,must_change_password) VALUES(?,?,?,?,?,1)',(stock_username,'Estoque','estoquista',pw_hash(stock_password),now()))
            if generated:
                cred=DATA_DIR/'credenciais-iniciais.txt'
                previous=cred.read_text(encoding='utf-8')+'\n' if cred.exists() else ''
                cred.write_text(previous+f'Usuário do estoque: {stock_username}\nSenha temporária do estoque: {stock_password}\nAltere a senha no primeiro acesso.\n',encoding='utf-8')
                try: cred.chmod(0o600)
                except OSError: pass
                print(f'Credencial temporária do estoque gravada em: {cred}')
@APP.on_event('startup')
def startup():
    init_db()
    threading.Thread(target=backup_worker,daemon=True,name='pdv-backup').start()

def backup_worker():
    """Cria snapshot ao iniciar e, depois, diariamente; conserva até 30 cópias."""
    while True:
        try:
            backup_dir=DATA_DIR/'backups'; backup_dir.mkdir(exist_ok=True)
            dest=backup_dir/f'pdv-{datetime.now().strftime("%Y%m%d-%H%M%S")}.sqlite3'
            with sqlite3.connect(DB,timeout=30) as src, sqlite3.connect(dest) as out:
                src.backup(out)
                if out.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise RuntimeError('Falha de integridade no snapshot')
            snapshots=sorted(backup_dir.glob('pdv-*.sqlite3'),key=lambda p:p.stat().st_mtime,reverse=True)
            for old in snapshots[30:]: old.unlink(missing_ok=True)
        except Exception:
            logging.exception('Não foi possível concluir o backup automático do PDV')
        time.sleep(24*60*60)

class Login(BaseModel): username:str; password:str
class ProductIn(BaseModel): barcode:Optional[str]=None; sku:str; name:str; description:str=''; category_id:Optional[int]=None; unit:str='unidade'; cost:float=Field(default=0,ge=0); price:float=Field(default=0,ge=0); stock:float=Field(default=0,ge=0); min_stock:float=Field(default=0,ge=0); active:bool=True
class MovementIn(BaseModel): product_id:int; kind:str; quantity:float=Field(ge=0); reason:str=Field(min_length=2,max_length=250)
class SaleItemIn(BaseModel): product_id:int; quantity:float=Field(gt=0)
class PaymentIn(BaseModel): method:str; amount:float=Field(gt=0); details:str=''; received_amount:Optional[float]=None; customer_name:Optional[str]=None; customer_key:Optional[str]=None
class SaleIn(BaseModel): items:list[SaleItemIn]; payments:list[PaymentIn]; discount:float=0; idempotency_key:str=Field(min_length=8,max_length=100)
class CancelIn(BaseModel): reason:str=Field(min_length=3,max_length=250)
class CashOpen(BaseModel): opening_amount:float=Field(default=0,ge=0)
class CashMove(BaseModel): kind:str; amount:float=Field(gt=0); reason:str=Field(min_length=2,max_length=250)
class CashClose(BaseModel): counted_amount:float=Field(ge=0)
class UserIn(BaseModel): username:str; name:str; role:str; password:str=Field(min_length=1)
class UserUpdate(BaseModel): username:str; name:str; role:str; active:bool=True; password:Optional[str]=Field(default=None,min_length=1)
class PasswordChange(BaseModel): current_password:str; new_password:str=Field(min_length=1)
class CreditCustomerIn(BaseModel): name:str=Field(min_length=1,max_length=120); reference:str=Field(min_length=1,max_length=160); phone:str=Field(default='9',max_length=30)
class CreditSettlementIn(BaseModel): amount:float=Field(gt=0); method:str; idempotency_key:str=Field(min_length=8,max_length=100)

def current_user(request:Request, authorization:Optional[str]=Header(None)):
    if not authorization or not authorization.startswith('Bearer '): raise HTTPException(401,'Faça login para continuar.')
    token=authorization[7:]
    c=connect()
    row=c.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1',(hashlib.sha256(token.encode()).hexdigest(),now())).fetchone(); c.close()
    if not row: raise HTTPException(401,'Sessão expirada. Entre novamente.')
    user=dict(row)
    allowed_during_password_change={'/api/me','/api/me/password','/api/logout'}
    if user.get('must_change_password') and request.url.path not in allowed_during_password_change:
        raise HTTPException(428,'Troque a senha temporária para continuar.')
    return user


def allow(*roles):
    def dep(user=Depends(current_user)):
        if user['role'] not in roles: raise HTTPException(403,'Seu perfil não tem permissão para esta operação.')
        return user
    return dep
def product_audit_snapshot(c,row):
    category=''
    if row['category_id'] is not None:
        found=c.execute('SELECT name FROM categories WHERE id=?',(row['category_id'],)).fetchone()
        category=found['name'] if found else ''
    return {'name':row['name'],'sku':row['sku'],'barcode':row['barcode'] or '',
            'category':category,'unit':row['unit'],'cost':row['cost_cents']/100,
            'price':row['price_cents']/100,'stock':row['stock'],
            'min_stock':row['min_stock'],'active':bool(row['active'])}

def audit_product_value(key,value):
    if value is None or value=='': return '—'
    if key in ('price','cost'): return 'R$ '+f'{float(value):,.2f}'.replace(',','X').replace('.',',').replace('X','.')
    if key=='active': return 'Ativo' if value else 'Inativo'
    if key=='stock' or key=='min_stock': return f'{float(value):g}'.replace('.',',')
    return str(value)

def product_out(r,include_cost=True):
    d=dict(r); cost_cents=d.pop('cost_cents'); d['price']=d.pop('price_cents')/100; d['low_stock']=d['stock']<=d['min_stock'];
    if include_cost: d['cost']=cost_cents/100
    return d

@APP.get('/api/status')
def status(): return {'sistema':'PDV Local','banco':'conectado','horario':now()}
@APP.post('/api/login')
def login(data:Login):
    c=connect(); u=c.execute('SELECT * FROM users WHERE username=? AND active=1',(data.username,)).fetchone()
    if not u or not pw_check(data.password,u['password_hash']): c.close(); raise HTTPException(401,'Usuário ou senha inválidos.')
    token=secrets.token_urlsafe(32); expiry=(datetime.now().astimezone()+timedelta(hours=12)).isoformat(timespec='seconds')
    c.execute('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),u['id'],expiry)); audit(c,u['id'],'login','sessao'); c.close()
    return {'token':token,'usuario':{'id':u['id'],'nome':u['name'],'usuario':u['username'],'perfil':u['role'],'must_change_password':bool(u['must_change_password'])},'expira_em':expiry}
@APP.post('/api/logout')
def logout(user=Depends(current_user), authorization:Optional[str]=Header(None)):
    token=authorization[7:]
    with transaction() as c: c.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),))
    return {'ok':True}
@APP.get('/api/me')
def me(user=Depends(current_user)): return {'id':user['id'],'nome':user['name'],'usuario':user['username'],'perfil':user['role'],'must_change_password':bool(user.get('must_change_password'))}
@APP.post('/api/me/password')
def change_password(data:PasswordChange,user=Depends(current_user),authorization:Optional[str]=Header(None)):
    if not pw_check(data.current_password,user['password_hash']): raise HTTPException(400,'A senha atual está incorreta.')
    token=authorization[7:] if authorization and authorization.startswith('Bearer ') else ''
    with transaction() as c:
        c.execute('UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?',(pw_hash(data.new_password),user['id']))
        c.execute('DELETE FROM sessions WHERE user_id=? AND token_hash<>?',(user['id'],hashlib.sha256(token.encode()).hexdigest()))
        audit(c,user['id'],'alteracao_senha','usuario',user['id'])
    return {'ok':True,'mensagem':'Senha alterada. Outras sessões foram encerradas.'}

@APP.get('/api/categories')
def categories(user=Depends(current_user)):
    c=connect(); r=[dict(x) for x in c.execute('SELECT * FROM categories ORDER BY name')]; c.close(); return r
@APP.get('/api/products')
def products(q:str='',active:Optional[bool]=None,limit:int=500,user=Depends(current_user)):
    c=connect(); sql='SELECT p.*,c.name category FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE 1=1'; args=[]
    if q: sql+=' AND (p.name LIKE ? OR p.sku LIKE ? OR p.barcode LIKE ?)'; args += [f'%{q}%']*3
    if active is not None: sql+=' AND p.active=?'; args.append(int(active))
    sql+=' ORDER BY p.name LIMIT ?'; args.append(min(max(limit,1),1000))
    rows=[product_out(r,include_cost=user['role'] in ('administrador','estoquista')) for r in c.execute(sql,args)]; c.close(); return rows
@APP.post('/api/products')
def create_product(data:ProductIn,user=Depends(allow('administrador','estoquista'))):
    with transaction() as c:
        if data.category_id and not c.execute('SELECT 1 FROM categories WHERE id=?',(data.category_id,)).fetchone(): raise HTTPException(400,'Categoria não encontrada.')
        try:
            cur=c.execute('INSERT INTO products(barcode,sku,name,description,category_id,unit,cost_cents,price_cents,stock,min_stock,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(data.barcode or None,data.sku.strip(),data.name.strip(),data.description,data.category_id,data.unit,money(data.cost),money(data.price),data.stock,data.min_stock,int(data.active),now(),now()))
        except sqlite3.IntegrityError as e: raise HTTPException(409,'Código de barras ou SKU já cadastrado.') from e
        pid=cur.lastrowid
        if data.stock: c.execute('INSERT INTO stock_movements(product_id,user_id,kind,quantity,balance_after,reason,created_at) VALUES(?,?,?,?,?,?,?)',(pid,user['id'],'entrada_inicial',data.stock,data.stock,'Estoque inicial do cadastro',now()))
        row=c.execute('SELECT * FROM products WHERE id=?',(pid,)).fetchone()
        snapshot=product_audit_snapshot(c,row)
        audit(c,user['id'],'cadastro','produto',pid,'Produto cadastrado: '+data.name,after=snapshot)
        row=c.execute('SELECT p.*,c.name category FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.id=?',(pid,)).fetchone()
    return product_out(row)
@APP.put('/api/products/{pid}')
def update_product(pid:int,data:ProductIn,user=Depends(allow('administrador','estoquista'))):
    with transaction() as c:
        old=c.execute('SELECT * FROM products WHERE id=?',(pid,)).fetchone()
        if not old: raise HTTPException(404,'Produto não encontrado.')
        before=product_audit_snapshot(c,old)
        try: c.execute('UPDATE products SET barcode=?,sku=?,name=?,description=?,category_id=?,unit=?,cost_cents=?,price_cents=?,min_stock=?,active=?,updated_at=? WHERE id=?',(data.barcode or None,data.sku.strip(),data.name.strip(),data.description,data.category_id,data.unit,money(data.cost),money(data.price),data.min_stock,int(data.active),now(),pid))
        except sqlite3.IntegrityError as e: raise HTTPException(409,'Código de barras ou SKU já cadastrado.') from e
        updated=c.execute('SELECT * FROM products WHERE id=?',(pid,)).fetchone()
        after=product_audit_snapshot(c,updated)
        labels={'name':'Nome','sku':'SKU','barcode':'Código de barras','category':'Categoria','unit':'Unidade','cost':'Custo','price':'Preço','stock':'Estoque','min_stock':'Estoque mínimo','active':'Situação'}
        verbs={'name':'Nome alterado','sku':'SKU alterado','barcode':'Código de barras alterado','category':'Categoria alterada','unit':'Unidade alterada','cost':'Custo alterado','price':'Preço alterado','stock':'Estoque alterado','min_stock':'Estoque mínimo alterado'}
        changed=[key for key in before if before[key]!=after[key]]
        descriptions=[]
        for key in changed:
            verb='Situação alterada' if key=='active' else verbs.get(key,labels[key]+' alterado')
            descriptions.append(f'{verb} de {audit_product_value(key,before[key])} para {audit_product_value(key,after[key])}')
        if changed==['active']:
            action='alteracao_status'; details='Alteração de status: '+(descriptions[0] if descriptions else 'sem diferença')
        elif changed==['price']:
            action='alteracao_preco'; details='Alteração de preço: '+(descriptions[0] if descriptions else 'sem diferença')
        elif changed==['stock']:
            action='alteracao_estoque'; details='Alteração de estoque: '+(descriptions[0] if descriptions else 'sem diferença')
        elif len(changed)==1:
            action='alteracao_'+changed[0]; details='Alteração de item: '+descriptions[0]
        else:
            action='alteracao_produto'; details='Alteração de item: '+'; '.join(descriptions) if descriptions else 'Alteração de item sem mudança detectável.'
        audit(c,user['id'],action,'produto',pid,details,before=before,after=after)
        row=c.execute('SELECT p.*,c.name category FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.id=?',(pid,)).fetchone()
    return product_out(row)
@APP.get('/api/products/barcode/{barcode}')
def by_barcode(barcode:str,user=Depends(current_user)):
    c=connect(); row=c.execute('SELECT p.*,c.name category FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.barcode=? AND p.active=1',(barcode,)).fetchone(); c.close()
    if not row: raise HTTPException(404,'Código não cadastrado.')
    return product_out(row,include_cost=user['role'] in ('administrador','estoquista'))
@APP.post('/api/stock/movement')
def stock_movement(data:MovementIn,user=Depends(allow('administrador','estoquista'))):
    if data.kind not in ('entrada','saida','ajuste','perda','avaria','vencimento'): raise HTTPException(400,'Tipo de movimentação inválido.')
    if data.quantity<=0 and data.kind!='ajuste': raise HTTPException(400,'A quantidade precisa ser maior que zero.')
    with transaction() as c:
        p=c.execute('SELECT * FROM products WHERE id=?',(data.product_id,)).fetchone()
        if not p: raise HTTPException(404,'Produto não encontrado.')
        qty=abs(data.quantity); new=p['stock']+qty if data.kind=='entrada' else (p['stock']-qty if data.kind in ('saida','perda','avaria','vencimento') else qty)
        if new < -1e-9: raise HTTPException(409,'Saldo insuficiente para esta saída.')
        c.execute('UPDATE products SET stock=?,updated_at=? WHERE id=?',(new,now(),p['id']))
        c.execute('INSERT INTO stock_movements(product_id,user_id,kind,quantity,balance_after,reason,created_at) VALUES(?,?,?,?,?,?,?)',(p['id'],user['id'],data.kind,qty if data.kind!='ajuste' else new-p['stock'],new,data.reason,now()))
        audit(c,user['id'],'alteracao_estoque','produto',p['id'],f'Alteração de estoque: saldo alterado de {p["stock"]:g} para {new:g}; motivo: {data.reason}',before={'stock':p['stock']},after={'stock':new})
    return {'saldo_atual':new}
@APP.get('/api/stock/movements')
def stock_history(q:str='',limit:int=300,user=Depends(allow('administrador','estoquista'))):
    c=connect(); rows=[dict(r) for r in c.execute('SELECT m.*,p.name produto,p.sku,u.name usuario FROM stock_movements m JOIN products p ON p.id=m.product_id JOIN users u ON u.id=m.user_id WHERE p.name LIKE ? OR p.sku LIKE ? ORDER BY m.id DESC LIMIT ?',(f'%{q}%',f'%{q}%',min(limit,1000)))]; c.close(); return rows
@APP.get('/api/stock/low')
def stock_low(user=Depends(allow('administrador','estoquista'))):
    c=connect(); rows=[product_out(r) for r in c.execute('SELECT p.*,c.name category FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.active=1 AND p.stock<=p.min_stock ORDER BY p.stock,p.name')]; c.close(); return rows

@APP.post('/api/sales')
def create_sale(data:SaleIn,user=Depends(allow('administrador','caixa'))):
    if not data.items or not data.payments: raise HTTPException(400,'Inclua produtos e ao menos uma forma de pagamento.')
    if data.discount > 0 and user['role'] != 'administrador': raise HTTPException(403,'Somente um administrador pode aplicar descontos.')
    with transaction() as c:
        existing=c.execute('SELECT id,number,subtotal_cents,discount_cents,total_cents FROM sales WHERE idempotency_key=?',(data.idempotency_key,)).fetchone()
        if existing:
            old_change=0
            for payment_row in c.execute("SELECT details FROM payments WHERE sale_id=? AND method='dinheiro'",(existing['id'],)):
                try: old_change+=int(json.loads(payment_row['details']).get('troco_centavos',0))
                except (ValueError,TypeError,AttributeError): pass
            return {'id':existing['id'],'numero':existing['number'],'subtotal':existing['subtotal_cents']/100,'desconto':existing['discount_cents']/100,'total':existing['total_cents']/100,'troco':old_change/100,'duplicada':True}
        if not c.execute("SELECT 1 FROM cash_sessions WHERE user_id=? AND status='aberto'",(user['id'],)).fetchone(): raise HTTPException(409,'Abra seu caixa antes de registrar uma venda.')
        subtotal=0; items=[]
        requested={}
        for it in data.items: requested[it.product_id]=requested.get(it.product_id,0)+it.quantity
        for product_id,quantity in requested.items():
            p=c.execute('SELECT * FROM products WHERE id=? AND active=1',(product_id,)).fetchone()
            if not p: raise HTTPException(404,'Um produto da venda não está disponível.')
            if p['stock']+1e-9 < quantity: raise HTTPException(409,f'Estoque insuficiente para {p["name"]}. Disponível: {p["stock"]:g}.')
            line=int(Decimal(str(p['price_cents']*quantity)).quantize(Decimal('1'),rounding=ROUND_HALF_UP)); subtotal+=line; items.append((p,quantity,line))
        discount=money(data.discount)
        if discount<0 or discount>subtotal: raise HTTPException(400,'Desconto inválido.')
        total=subtotal-discount; payments=[]; change_cents=0; fiado_customer=None; fiado_key=None
        for payment in data.payments:
            method=payment.method.strip().lower(); amount=money(payment.amount); details=payment.details
            if method=='dinheiro':
                received=money(payment.received_amount) if payment.received_amount is not None else amount
                if received<amount: raise HTTPException(400,'Valor recebido em dinheiro inferior à parte atribuída a dinheiro.')
                change_cents+=received-amount
                details=json.dumps({'observacao':details,'valor_recebido_centavos':received,'troco_centavos':received-amount},ensure_ascii=False)
            elif method=='fiado':
                if payment.received_amount is not None: raise HTTPException(400,'Valor recebido em dinheiro não se aplica a fiado.')
                if fiado_customer is not None: raise HTTPException(400,'Use somente uma parcela de fiado por venda.')
                if payment.customer_key:
                    customer=c.execute('SELECT customer_key,name FROM credit_customers WHERE customer_key=?',(payment.customer_key,)).fetchone()
                    if not customer: raise HTTPException(404,'Cliente do fiado não encontrado; atualize a lista e selecione novamente.')
                    fiado_customer,fiado_key=customer['name'],customer['customer_key']
                else:
                    fiado_customer,fiado_key=normalized_customer(payment.customer_name)
                    c.execute("INSERT OR IGNORE INTO credit_customers(customer_key,name,reference,created_at,created_by) VALUES(?,?, '', ?,?)",(fiado_key,fiado_customer,now(),user['id']))
                    customer=c.execute('SELECT customer_key,name FROM credit_customers WHERE customer_key=?',(fiado_key,)).fetchone()
                    fiado_customer,fiado_key=customer['name'],customer['customer_key']
                details=json.dumps({'cliente':fiado_customer,'observacao':details},ensure_ascii=False)
            elif payment.received_amount is not None: raise HTTPException(400,'Valor recebido é aplicável somente a pagamento em dinheiro.')
            payments.append((method,amount,details))
        if any(m not in ('dinheiro','pix','cartao_credito','cartao_debito','fiado') for m,_,_ in payments): raise HTTPException(400,'Forma de pagamento inválida.')
        if sum(1 for m,_,_ in payments if m=='fiado')>1: raise HTTPException(400,'Use somente uma parcela de fiado por venda.')
        if sum(x[1] for x in payments)!=total: raise HTTPException(400,'A soma dos pagamentos precisa corresponder ao total da venda.')
        number=datetime.now().strftime('%Y%m%d')+'-'+secrets.token_hex(3).upper()
        cur=c.execute('INSERT INTO sales(number,operator_id,status,subtotal_cents,discount_cents,total_cents,idempotency_key,created_at) VALUES(?,?,?,?,?,?,?,?)',(number,user['id'],'concluida',subtotal,discount,total,data.idempotency_key,now())); sid=cur.lastrowid
        for p,qty,line in items:
            c.execute('INSERT INTO sale_items(sale_id,product_id,sku,product_name,quantity,unit_price_cents,subtotal_cents) VALUES(?,?,?,?,?,?,?)',(sid,p['id'],p['sku'],p['name'],qty,p['price_cents'],line))
            balance=p['stock']-qty; c.execute('UPDATE products SET stock=?,updated_at=? WHERE id=?',(balance,now(),p['id']))
            c.execute('INSERT INTO stock_movements(product_id,user_id,kind,quantity,balance_after,reason,ref_type,ref_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(p['id'],user['id'],'venda',-qty,balance,'Baixa automática da venda '+number,'venda',sid,now()))
        for method,amount,details in payments: c.execute('INSERT INTO payments(sale_id,method,amount_cents,details) VALUES(?,?,?,?)',(sid,method,amount,details))
        fiado_payment=next(((amount,details) for method,amount,details in payments if method=='fiado'),None)
        if fiado_payment:
            amount,details=fiado_payment
            c.execute('INSERT INTO credit_entries(sale_id,customer_name,customer_key,amount_cents,created_at) VALUES(?,?,?,?,?)',(sid,fiado_customer,fiado_key,amount,now()))
            audit(c,user['id'],'fiado_registrado','venda',sid,f'{fiado_customer} | {number} | {amount/100:.2f}')
        audit(c,user['id'],'venda_concluida','venda',sid,number)
    return {'id':sid,'numero':number,'subtotal':subtotal/100,'desconto':discount/100,'total':total/100,'troco':change_cents/100,'duplicada':False}

def sale_status(c,sid,stored_status):
    if stored_status=='cancelada': return 'cancelada'
    pending=c.execute("SELECT 1 FROM payments WHERE sale_id=? AND method='pix' AND provider='asaas' AND status IN ('pendente','indefinido') LIMIT 1",(sid,)).fetchone()
    return 'aguardando_pix' if pending else stored_status

def credit_balance_cents(c,customer_key):
    debt=c.execute("SELECT COALESCE(SUM(ce.amount_cents),0) FROM credit_entries ce JOIN sales s ON s.id=ce.sale_id WHERE ce.customer_key=? AND s.status='concluida'",(customer_key,)).fetchone()[0]
    paid=c.execute("SELECT COALESCE(SUM(amount_cents),0) FROM credit_settlements WHERE customer_key=? AND status='confirmado'",(customer_key,)).fetchone()[0]
    pending=c.execute("SELECT COALESCE(SUM(amount_cents),0) FROM credit_settlements WHERE customer_key=? AND status IN ('pendente','indefinido')",(customer_key,)).fetchone()[0]
    return debt-paid,pending

def customer_out(c,row):
    balance,pending=credit_balance_cents(c,row['customer_key'])
    return {'key':row['customer_key'],'name':row['name'],'reference':row['reference'],'phone':row['phone'],'balance':balance/100,'pending_pix':pending/100}

@APP.get('/api/fiado/customers')
def list_credit_customers(q:str='',user=Depends(allow('administrador','caixa'))):
    qkey=customer_search_key(q) if q.strip() else ''
    c=connect(); rows=c.execute('SELECT customer_key,name,reference,phone,created_at FROM credit_customers ORDER BY name COLLATE NOCASE').fetchall(); c.close()
    items=[]
    for row in rows:
        if qkey and qkey not in customer_search_key(row['name']) and qkey not in customer_search_key(row['reference']): continue
        items.append({'key':row['customer_key'],'name':row['name'],'reference':row['reference'],'phone':row['phone'],'created_at':row['created_at']})
    return {'items':items,'total':len(items)}

@APP.post('/api/fiado/customers')
def create_credit_customer(data:CreditCustomerIn,user=Depends(allow('administrador','caixa'))):
    name,key=normalized_customer(data.name); reference=' '.join(data.reference.split()); phone=' '.join(data.phone.split())
    if not reference or len(reference)>160: raise HTTPException(400,'Informe uma referência (até 160 caracteres).')
    if len(phone)>30: raise HTTPException(400,'O contato deve ter até 30 caracteres.')
    with transaction() as c:
        if c.execute('SELECT 1 FROM credit_customers WHERE customer_key=?',(key,)).fetchone(): raise HTTPException(409,'Já existe um usuário com esse nome. Pesquise e selecione o cadastro existente.')
        c.execute('INSERT INTO credit_customers(customer_key,name,reference,phone,created_at,created_by) VALUES(?,?,?,?,?,?)',(key,name,reference,phone,now(),user['id']))
        audit(c,user['id'],'cliente_fiado_criado','cliente_fiado',key,f'{name} | referência: {reference}')
    return {'key':key,'name':name,'reference':reference,'phone':phone}


@APP.put('/api/fiado/customers/{customer_key}')
def update_credit_customer(customer_key:str,data:CreditCustomerIn,user=Depends(allow('administrador','caixa'))):
    name,new_key=normalized_customer(data.name); reference=' '.join(data.reference.split()); phone=' '.join(data.phone.split())
    if not reference or len(reference)>160: raise HTTPException(400,'Informe uma referência (até 160 caracteres).')
    if len(phone)>30: raise HTTPException(400,'O contato deve ter até 30 caracteres.')
    with transaction() as c:
        old=c.execute('SELECT * FROM credit_customers WHERE customer_key=?',(customer_key,)).fetchone()
        if not old: raise HTTPException(404,'Cliente não encontrado.')
        conflict=c.execute('SELECT 1 FROM credit_customers WHERE customer_key=? AND customer_key<>?',(new_key,customer_key)).fetchone()
        if conflict: raise HTTPException(409,'Já existe outro cliente com esse nome. Use o cadastro existente.')
        if new_key!=customer_key:
            c.execute('INSERT INTO credit_customers(customer_key,name,reference,phone,created_at,created_by) VALUES(?,?,?,?,?,?)',(new_key,name,reference,phone,old['created_at'],old['created_by']))
            c.execute('UPDATE credit_entries SET customer_key=?,customer_name=? WHERE customer_key=?',(new_key,name,customer_key))
            c.execute('UPDATE credit_settlements SET customer_key=? WHERE customer_key=?',(new_key,customer_key))
            c.execute('DELETE FROM credit_customers WHERE customer_key=?',(customer_key,))
        else:
            c.execute('UPDATE credit_customers SET name=?,reference=?,phone=? WHERE customer_key=?',(name,reference,phone,customer_key))
            c.execute('UPDATE credit_entries SET customer_name=? WHERE customer_key=?',(name,customer_key))
        audit(c,user['id'],'cliente_fiado_alterado','cliente_fiado',new_key,f'{old["name"]} → {name} | referência: {reference}')
    return {'key':new_key,'name':name,'reference':reference,'phone':phone}

@APP.get('/api/fiados')
def fiado_customers(q:str='',user=Depends(allow('administrador','caixa'))):
    qkey=customer_search_key(q) if q.strip() else ''
    c=connect(); rows=c.execute("""SELECT cc.customer_key,cc.name,cc.reference,cc.phone,
      (SELECT MAX(ce.created_at) FROM credit_entries ce JOIN sales s ON s.id=ce.sale_id WHERE ce.customer_key=cc.customer_key AND s.status='concluida') last_fiado
      FROM credit_customers cc
      ORDER BY cc.name COLLATE NOCASE""").fetchall()
    items=[]
    for row in rows:
        if qkey and qkey not in customer_search_key(row['name']) and qkey not in customer_search_key(row['reference']): continue
        item=customer_out(c,row); item['last_fiado']=row['last_fiado']; items.append(item)
    c.close(); return {'items':items,'total':len(items)}

@APP.get('/api/fiados/{customer_key}')
def fiado_history(customer_key:str,user=Depends(allow('administrador','caixa'))):
    c=connect(); customer=c.execute('SELECT customer_key,name,reference,phone FROM credit_customers WHERE customer_key=?',(customer_key,)).fetchone()
    if not customer: c.close(); raise HTTPException(404,'Cliente não encontrado.')
    debt_rows=c.execute("SELECT ce.created_at,ce.amount_cents,s.number FROM credit_entries ce JOIN sales s ON s.id=ce.sale_id WHERE ce.customer_key=? AND s.status='concluida'",(customer_key,)).fetchall()
    settlement_rows=c.execute('SELECT id,created_at,confirmed_at,amount_cents,method,status FROM credit_settlements WHERE customer_key=?',(customer_key,)).fetchall()
    balance,pending=credit_balance_cents(c,customer_key); c.close()
    events=[{'created_at':r['created_at'],'kind':'fiado','label':'Compra fiada · venda '+r['number'],'amount':r['amount_cents']/100,'status':'registrado'} for r in debt_rows]
    for r in settlement_rows:
        events.append({'id':r['id'],'created_at':r['confirmed_at'] or r['created_at'],'kind':'pagamento','method':r['method'],'label':'Pagamento · '+r['method'].replace('_',' '),'amount':r['amount_cents']/100,'status':r['status']})
    events.sort(key=lambda x:x['created_at'],reverse=True)
    return {'customer_name':customer['name'],'reference':customer['reference'],'phone':customer['phone'],'items':events,'balance':balance/100,'pending_pix':pending/100}

@APP.post('/api/fiados/{customer_key}/settlements')
def settle_fiado(customer_key:str,data:CreditSettlementIn,user=Depends(allow('administrador','caixa'))):
    method=data.method.strip().lower()
    if method not in ('dinheiro','cartao_credito','cartao_debito','pix'): raise HTTPException(400,'Forma de pagamento inválida.')
    amount=money(data.amount)
    if amount<=0: raise HTTPException(400,'Informe um valor maior que R$ 0,00.')
    with transaction() as c:
        existing=c.execute('SELECT * FROM credit_settlements WHERE idempotency_key=?',(data.idempotency_key,)).fetchone()
        if existing:
            if existing['customer_key']!=customer_key or existing['amount_cents']!=amount or existing['method']!=method: raise HTTPException(409,'A chave desta tentativa já foi usada para outro pagamento.')
            return {'id':existing['id'],'status':existing['status'],'checkout_url':existing['checkout_url'],'amount':amount/100,'duplicada':True}
        customer=c.execute('SELECT customer_key FROM credit_customers WHERE customer_key=?',(customer_key,)).fetchone()
        if not customer: raise HTTPException(404,'Cliente não encontrado.')
        cash=c.execute("SELECT id FROM cash_sessions WHERE user_id=? AND status='aberto' ORDER BY id DESC LIMIT 1",(user['id'],)).fetchone()
        if not cash: raise HTTPException(409,'Abra seu caixa antes de receber pagamento de fiado.')
        balance,pending=credit_balance_cents(c,customer_key); available=balance-pending
        if balance<=0: raise HTTPException(409,'Este cliente não possui saldo de fiado em aberto.')
        if amount>available: raise HTTPException(409,f'Valor excede o disponível para recebimento ({max(available,0)/100:.2f}). Há Pix pendente ou saldo já quitado.')
        status='confirmado'; external_ref='MANUAL-FIADO-'+secrets.token_hex(10).upper(); stamp=now()
        cur=c.execute('INSERT INTO credit_settlements(customer_key,amount_cents,method,status,provider,external_reference,operator_id,cash_session_id,idempotency_key,created_at,confirmed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',(customer_key,amount,method,status,None,external_ref,user['id'],cash['id'],data.idempotency_key,stamp,stamp)); settlement_id=cur.lastrowid
        audit(c,user['id'],'fiado_pagamento_registrado','fiado_pagamento',settlement_id,f'{customer_key} | {method} | {amount/100:.2f}')
    with connect() as c: balance,_=credit_balance_cents(c,customer_key)
    return {'id':settlement_id,'status':'confirmado','amount':amount/100,'balance':balance/100,'duplicada':False}


@APP.post('/api/fiado/settlements/{settlement_id}/confirm-manual')
def confirm_legacy_fiado_pix(settlement_id:int,user=Depends(allow('administrador','caixa'))):
    with transaction() as c:
        row=c.execute('SELECT * FROM credit_settlements WHERE id=?',(settlement_id,)).fetchone()
        if not row: raise HTTPException(404,'Pagamento de fiado não encontrado.')
        if row['method']!='pix' or row['provider']!='asaas' or row['status'] not in ('pendente','indefinido'):
            raise HTTPException(409,'Este registro não é um Pix antigo pendente que possa ser conciliado manualmente.')
        c.execute("UPDATE credit_settlements SET status='confirmado',confirmed_at=? WHERE id=?",(now(),settlement_id))
        audit(c,user['id'],'fiado_pix_legado_confirmado_manual','fiado_pagamento',settlement_id,'Conferido pelo operador no comprovante/extrato bancário.')
    return {'ok':True,'status':'confirmado'}

@APP.post('/api/fiado/settlements/{settlement_id}/cancel-manual')
def cancel_legacy_fiado_pix(settlement_id:int,user=Depends(allow('administrador','caixa'))):
    with transaction() as c:
        row=c.execute('SELECT * FROM credit_settlements WHERE id=?',(settlement_id,)).fetchone()
        if not row: raise HTTPException(404,'Pagamento de fiado não encontrado.')
        if row['method']!='pix' or row['provider']!='asaas' or row['status'] not in ('pendente','indefinido'):
            raise HTTPException(409,'Este registro não é um Pix antigo pendente que possa ser cancelado manualmente.')
        c.execute("UPDATE credit_settlements SET status='cancelado' WHERE id=?",(settlement_id,))
        audit(c,user['id'],'fiado_pix_legado_cancelado_manual','fiado_pagamento',settlement_id,'Cancelado pelo operador; nenhuma quitação foi lançada.')
    return {'ok':True,'status':'cancelado'}

@APP.get('/api/fiado/settlements/{settlement_id}')
def fiado_settlement_status(settlement_id:int,user=Depends(allow('administrador','caixa'))):
    c=connect(); row=c.execute('SELECT * FROM credit_settlements WHERE id=?',(settlement_id,)).fetchone()
    if not row: c.close(); raise HTTPException(404,'Pagamento de fiado não encontrado.')
    # Administrador e Caixa têm acesso ao estado do Pix; os dados retornados são limitados ao pagamento.
    balance,pending=credit_balance_cents(c,row['customer_key']); c.close()
    return {'id':row['id'],'status':row['status'],'method':row['method'],'amount':row['amount_cents']/100,'balance':balance/100,'pending_pix':pending/100}


@APP.post('/api/sales/{sid}/confirm-manual-pix')
def confirm_legacy_sale_pix(sid:int,user=Depends(allow('administrador','caixa'))):
    with transaction() as c:
        sale=c.execute('SELECT * FROM sales WHERE id=?',(sid,)).fetchone()
        if not sale or (user['role']!='administrador' and sale['operator_id']!=user['id']): raise HTTPException(404,'Venda não encontrada.')
        payment=c.execute("SELECT * FROM payments WHERE sale_id=? AND method='pix' AND provider='asaas' AND status IN ('pendente','indefinido') ORDER BY id DESC LIMIT 1",(sid,)).fetchone()
        if not payment: raise HTTPException(409,'Esta venda não tem um Pix antigo pendente para conciliar.')
        c.execute("UPDATE payments SET status='confirmado' WHERE id=?",(payment['id'],))
        audit(c,user['id'],'pix_legado_confirmado_manual','venda',sid,'Conferido pelo operador no comprovante/extrato bancário.')
    return {'ok':True,'status':'confirmado'}

@APP.get('/api/sales')
def sales(q:str='',limit:int=200,user=Depends(allow('administrador','caixa'))):
    c=connect(); sql='SELECT s.*,u.name operador FROM sales s JOIN users u ON u.id=s.operator_id WHERE s.number LIKE ?'; args=[f'%{q}%']
    if user['role']!='administrador': sql+=' AND s.operator_id=?'; args.append(user['id'])
    sql+=' ORDER BY s.id DESC LIMIT ?'; args.append(min(limit,1000)); rows=[dict(r) for r in c.execute(sql,args)]
    for r in rows:
        r['status']=sale_status(c,r['id'],r['status']); r['subtotal']=r.pop('subtotal_cents')/100; r['desconto']=r.pop('discount_cents')/100; r['total']=r.pop('total_cents')/100
    c.close()
    return rows
@APP.get('/api/sales/{sid}')
def sale_detail(sid:int,user=Depends(allow('administrador','caixa'))):
    c=connect(); sql='SELECT s.*,u.name operador FROM sales s JOIN users u ON u.id=s.operator_id WHERE s.id=?'; args=[sid]
    if user['role']!='administrador': sql+=' AND s.operator_id=?'; args.append(user['id'])
    s=c.execute(sql,args).fetchone()
    if not s: c.close(); raise HTTPException(404,'Venda não encontrada.')
    d=dict(s); d['items']=[dict(r) for r in c.execute('SELECT * FROM sale_items WHERE sale_id=?',(sid,))]; d['payments']=[dict(r) for r in c.execute('SELECT * FROM payments WHERE sale_id=?',(sid,))]; d['status']=sale_status(c,sid,d['status']); c.close(); return d
@APP.get('/api/receipts')
def receipts(q:str='',limit:int=50,offset:int=0,user=Depends(allow('administrador','caixa'))):
    q=q.strip()
    if len(q)==10 and q[2]=='/' and q[5]=='/':
        try: q=datetime.strptime(q,'%d/%m/%Y').strftime('%Y-%m-%d')
        except ValueError: pass
    where='(s.number LIKE ? OR s.created_at LIKE ?)'; args=[f'%{q}%',f'%{q}%']
    if user['role']!='administrador': where+=' AND s.operator_id=?'; args.append(user['id'])
    limit=min(max(limit,1),100); offset=max(offset,0)
    c=connect(); total=c.execute(f'SELECT COUNT(*) FROM sales s WHERE {where}',args).fetchone()[0]
    rows=[dict(r) for r in c.execute(f'SELECT s.id,s.number,s.created_at,s.status,s.total_cents,u.name operador FROM sales s JOIN users u ON u.id=s.operator_id WHERE {where} ORDER BY s.id DESC LIMIT ? OFFSET ?',(*args,limit,offset))]
    for row in rows: row['status']=sale_status(c,row['id'],row['status']); row['total']=row.pop('total_cents')/100
    c.close()
    return {'items':rows,'total':total,'limit':limit,'offset':offset}
@APP.post('/api/sales/{sid}/cancel')
def cancel_sale(sid:int,data:CancelIn,user=Depends(allow('administrador'))):
    with transaction() as c:
        s=c.execute('SELECT * FROM sales WHERE id=?',(sid,)).fetchone()
        if not s: raise HTTPException(404,'Venda não encontrada.')
        if s['status']=='cancelada': raise HTTPException(409,'Esta venda já foi cancelada.')
        c.execute("UPDATE payments SET status='cancelado' WHERE sale_id=? AND provider='asaas' AND status IN ('pendente','indefinido')",(sid,))
        c.execute('UPDATE sales SET status=?,canceled_at=?,canceled_by=?,cancel_reason=? WHERE id=?',('cancelada',now(),user['id'],data.reason,sid))
        for it in c.execute('SELECT * FROM sale_items WHERE sale_id=?',(sid,)).fetchall():
            p=c.execute('SELECT stock FROM products WHERE id=?',(it['product_id'],)).fetchone(); balance=p['stock']+it['quantity']
            c.execute('UPDATE products SET stock=?,updated_at=? WHERE id=?',(balance,now(),it['product_id']))
            c.execute('INSERT INTO stock_movements(product_id,user_id,kind,quantity,balance_after,reason,ref_type,ref_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(it['product_id'],user['id'],'estorno_venda',it['quantity'],balance,'Estorno da venda '+s['number']+': '+data.reason,'venda',sid,now()))
        audit(c,user['id'],'cancelamento_venda','venda',sid,data.reason)
    return {'ok':True,'mensagem':'Venda cancelada e estoque estornado.'}

@APP.post('/api/cash/open')
def cash_open(data:CashOpen,user=Depends(allow('administrador','caixa'))):
    with transaction() as c:
        if c.execute("SELECT 1 FROM cash_sessions WHERE user_id=? AND status='aberto'",(user['id'],)).fetchone(): raise HTTPException(409,'Você já possui um caixa aberto.')
        cur=c.execute('INSERT INTO cash_sessions(user_id,opening_cents,opened_at) VALUES(?,?,?)',(user['id'],money(data.opening_amount),now())); audit(c,user['id'],'abertura_caixa','caixa',cur.lastrowid)
    return {'id':cur.lastrowid,'mensagem':'Caixa aberto.'}
@APP.get('/api/cash/current')
def cash_current(user=Depends(allow('administrador','caixa'))):
    c=connect(); r=c.execute("SELECT * FROM cash_sessions WHERE user_id=? AND status='aberto' ORDER BY id DESC LIMIT 1",(user['id'],)).fetchone(); c.close(); return dict(r) if r else None
@APP.post('/api/cash/movement')
def cash_movement(data:CashMove,user=Depends(allow('administrador','caixa'))):
    if data.kind not in ('entrada','retirada'): raise HTTPException(400,'Tipo inválido.')
    with transaction() as c:
        cs=c.execute("SELECT id FROM cash_sessions WHERE user_id=? AND status='aberto'",(user['id'],)).fetchone()
        if not cs: raise HTTPException(409,'Abra o caixa antes de registrar movimentações.')
        c.execute('INSERT INTO cash_movements(cash_session_id,user_id,kind,amount_cents,reason,created_at) VALUES(?,?,?,?,?,?)',(cs['id'],user['id'],data.kind,money(data.amount),data.reason,now())); audit(c,user['id'],'movimentacao_caixa','caixa',cs['id'],data.kind+': '+data.reason)
    return {'ok':True}
def cash_totals(c,csid):
    sales=c.execute("SELECT p.method,COALESCE(SUM(p.amount_cents),0) total FROM payments p JOIN sales s ON s.id=p.sale_id WHERE s.status='concluida' AND p.status='confirmado' AND p.method!='fiado' AND s.operator_id=(SELECT user_id FROM cash_sessions WHERE id=?) AND s.created_at >= (SELECT opened_at FROM cash_sessions WHERE id=?) GROUP BY p.method",(csid,csid)).fetchall()
    ret={r['method']:r['total'] for r in sales}
    settlements=c.execute("SELECT method,COALESCE(SUM(amount_cents),0) total FROM credit_settlements WHERE cash_session_id=? AND status='confirmado' GROUP BY method",(csid,)).fetchall()
    for r in settlements: ret[r['method']]=ret.get(r['method'],0)+r['total']
    moves=c.execute('SELECT kind,COALESCE(SUM(amount_cents),0) total FROM cash_movements WHERE cash_session_id=? GROUP BY kind',(csid,)).fetchall()
    cash_expected=c.execute('SELECT opening_cents FROM cash_sessions WHERE id=?',(csid,)).fetchone()['opening_cents']+ret.get('dinheiro',0)
    for m in moves: cash_expected += m['total'] if m['kind']=='entrada' else -m['total']
    return ret,cash_expected
@APP.post('/api/cash/close')
def cash_close(data:CashClose,user=Depends(allow('administrador','caixa'))):
    with transaction() as c:
        cs=c.execute("SELECT * FROM cash_sessions WHERE user_id=? AND status='aberto'",(user['id'],)).fetchone()
        if not cs: raise HTTPException(409,'Não há caixa aberto.')
        pending=c.execute("SELECT COUNT(*) FROM payments p JOIN sales s ON s.id=p.sale_id WHERE s.operator_id=? AND s.created_at>=? AND p.provider='asaas' AND p.status IN ('pendente','indefinido')",(user['id'],cs['opened_at'])).fetchone()[0]
        pending+=c.execute("SELECT COUNT(*) FROM credit_settlements WHERE cash_session_id=? AND provider='asaas' AND status IN ('pendente','indefinido')",(cs['id'],)).fetchone()[0]
        if pending: raise HTTPException(409,'Há Pix iniciado na versão anterior aguardando conciliação. Confira o comprovante bancário e confirme manualmente ou cancele o registro antes de fechar o caixa.')
        totals,expected=cash_totals(c,cs['id']); counted=money(data.counted_amount); diff=counted-expected
        c.execute("UPDATE cash_sessions SET status='fechado',closing_cents=?,expected_cents=?,difference_cents=?,closed_at=? WHERE id=?",(counted,expected,diff,now(),cs['id'])); audit(c,user['id'],'fechamento_caixa','caixa',cs['id'])
    return {'esperado_dinheiro':expected/100,'contado':counted/100,'diferenca':diff/100,'por_forma':{k:v/100 for k,v in totals.items()}}
@APP.get('/api/cash/history')
def cash_history(user=Depends(allow('administrador','caixa'))):
    c=connect(); query='SELECT cs.*,u.name operador FROM cash_sessions cs JOIN users u ON u.id=cs.user_id'
    args=()
    if user['role']!='administrador': query+=' WHERE cs.user_id=?'; args=(user['id'],)
    rows=[dict(r) for r in c.execute(query+' ORDER BY cs.id DESC LIMIT 200',args)]; c.close(); return rows

@APP.get('/api/dashboard')
def dashboard(user=Depends(allow('administrador','caixa'))):
    c=connect(); day=datetime.now().astimezone().date().isoformat(); start=day+'T00:00:00'
    owner_clause=' AND operator_id=?' if user['role']=='caixa' else ''; owner_args=(user['id'],) if owner_clause else ()
    gross=c.execute("SELECT COALESCE(SUM(subtotal_cents),0) FROM sales WHERE status='concluida' AND created_at>=? AND id NOT IN (SELECT sale_id FROM payments WHERE status IN ('pendente','indefinido'))"+owner_clause,(start,*owner_args)).fetchone()[0]
    disc=c.execute("SELECT COALESCE(SUM(discount_cents),0) FROM sales WHERE status='concluida' AND created_at>=? AND id NOT IN (SELECT sale_id FROM payments WHERE status IN ('pendente','indefinido'))"+owner_clause,(start,*owner_args)).fetchone()[0]
    count=c.execute("SELECT COUNT(*) FROM sales WHERE status='concluida' AND created_at>=? AND id NOT IN (SELECT sale_id FROM payments WHERE status IN ('pendente','indefinido'))"+owner_clause,(start,*owner_args)).fetchone()[0]
    low=c.execute('SELECT COUNT(*) FROM products WHERE active=1 AND stock<=min_stock').fetchone()[0]
    zeros=c.execute('SELECT COUNT(*) FROM products WHERE active=1 AND stock<=0').fetchone()[0]
    top=[dict(r) for r in c.execute("SELECT si.product_name nome,SUM(si.quantity) quantidade FROM sale_items si JOIN sales s ON s.id=si.sale_id WHERE s.status='concluida' AND s.created_at>=? AND NOT EXISTS (SELECT 1 FROM payments p2 WHERE p2.sale_id=s.id AND p2.status IN ('pendente','indefinido'))"+(' AND s.operator_id=?' if owner_clause else '')+" GROUP BY si.product_id ORDER BY quantidade DESC LIMIT 5",(start,*owner_args))]
    pm=[dict(r) for r in c.execute("SELECT p.method forma, SUM(p.amount_cents)/100.0 valor FROM payments p JOIN sales s ON s.id=p.sale_id WHERE s.status='concluida' AND p.status='confirmado' AND p.method!='fiado' AND s.created_at>=?"+(' AND s.operator_id=?' if owner_clause else '')+" GROUP BY p.method",(start,*owner_args))]
    settled=c.execute("SELECT method forma,SUM(amount_cents)/100.0 valor FROM credit_settlements WHERE status='confirmado' AND confirmed_at>=?"+(' AND operator_id=?' if owner_clause else '')+" GROUP BY method",(start,*owner_args)).fetchall()
    pm_map={item['forma']:item for item in pm}
    for item in settled:
        entry=pm_map.get(item['forma'])
        if entry: entry['valor']+=item['valor']
        else: new_item={'forma':item['forma'],'valor':item['valor']}; pm.append(new_item); pm_map[item['forma']]=new_item
    c.close(); return {'vendas_brutas':gross/100,'descontos':disc/100,'vendas_liquidas':(gross-disc)/100,'quantidade_vendas':count,'ticket_medio':((gross-disc)/100/count if count else 0),'estoque_baixo':low,'sem_estoque':zeros,'mais_vendidos':top,'por_pagamento':pm}
@APP.get('/api/reports/payments')
def report_payments(user=Depends(allow('administrador'))):
    c=connect(); rows=[dict(r) for r in c.execute("SELECT p.method forma,COUNT(DISTINCT s.id) vendas,COUNT(*) transacoes,SUM(p.amount_cents) cents FROM payments p JOIN sales s ON s.id=p.sale_id WHERE s.status='concluida' AND p.status='confirmado' AND p.method!='fiado' GROUP BY p.method")]
    by_method={r['forma']:r for r in rows}
    for r in c.execute("SELECT method forma,COUNT(*) transacoes,SUM(amount_cents) cents FROM credit_settlements WHERE status='confirmado' GROUP BY method"):
        item=by_method.get(r['forma'])
        if item: item['transacoes']+=r['transacoes']; item['cents']+=r['cents']
        else: item={'forma':r['forma'],'vendas':0,'transacoes':r['transacoes'],'cents':r['cents']}; rows.append(item); by_method[r['forma']]=item
    for item in rows: item['valor']=item.pop('cents')/100
    c.close(); return rows
@APP.get('/api/products/export.csv')
def export_products(user=Depends(allow('administrador','estoquista'))):
    c=connect(); rows=c.execute('SELECT barcode,sku,name,description,unit,cost_cents,price_cents,stock,min_stock,active FROM products ORDER BY name').fetchall(); c.close()
    out=io.StringIO(); w=csv.writer(out,delimiter=';'); w.writerow(['codigo_barras','sku','nome','descricao','unidade','custo','preco','estoque','estoque_minimo','ativo'])
    for r in rows: w.writerow([r['barcode'],r['sku'],r['name'],r['description'],r['unit'],f"{r['cost_cents']/100:.2f}".replace('.',','),f"{r['price_cents']/100:.2f}".replace('.',','),str(r['stock']).replace('.',','),str(r['min_stock']).replace('.',','),r['active']])
    return Response('\ufeff'+out.getvalue(),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename=produtos.csv'})
@APP.post('/api/products/import.csv')
async def import_products(request:Request,user=Depends(allow('administrador','estoquista'))):
    raw=(await request.body()).decode('utf-8-sig'); reader=csv.DictReader(io.StringIO(raw),delimiter=';'); n=0
    with transaction() as c:
        for row in reader:
            if not row.get('sku') or not row.get('nome'): continue
            try:
                cur=c.execute('INSERT INTO products(barcode,sku,name,description,unit,cost_cents,price_cents,stock,min_stock,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(row.get('codigo_barras') or None,row['sku'],row['nome'],row.get('descricao',''),row.get('unidade','unidade'),money(row.get('custo','0')),money(row.get('preco','0')),number(row.get('estoque','0')),number(row.get('estoque_minimo','0')),int(row.get('ativo','1') or 1),now(),now())); imported_stock=number(row.get('estoque','0'));
                if imported_stock: c.execute('INSERT INTO stock_movements(product_id,user_id,kind,quantity,balance_after,reason,created_at) VALUES(?,?,?,?,?,?,?)',(cur.lastrowid,user['id'],'entrada_inicial_importacao',imported_stock,imported_stock,'Importação CSV',now()))
                n+=1
            except sqlite3.IntegrityError: continue
        audit(c,user['id'],'importacao','produtos',details=f'{n} produtos')
    return {'importados':n}
@APP.get('/api/users')
def users(user=Depends(allow('administrador'))):
    c=connect(); rows=[dict(r) for r in c.execute('SELECT id,username,name,role,active,created_at,must_change_password FROM users ORDER BY name')]; c.close(); return rows
@APP.post('/api/users')
def create_user(data:UserIn,user=Depends(allow('administrador'))):
    username=data.username.strip(); name=data.name.strip()
    if data.role not in ('administrador','caixa','estoquista') or not username or not name: raise HTTPException(400,'Perfil inválido ou nome/usuário vazio.')
    try:
        with transaction() as c:
            cur=c.execute('INSERT INTO users(username,name,role,password_hash,created_at) VALUES(?,?,?,?,?)',(username,name,data.role,pw_hash(data.password),now())); audit(c,user['id'],'cadastro','usuario',cur.lastrowid,username)
    except sqlite3.IntegrityError as e: raise HTTPException(409,'Nome de usuário já existe.') from e
    return {'id':cur.lastrowid}
@APP.put('/api/users/{uid}')
def update_user(uid:int,data:UserUpdate,user=Depends(allow('administrador'))):
    username=data.username.strip(); name=data.name.strip()
    if data.role not in ('administrador','caixa','estoquista') or not username or not name: raise HTTPException(400,'Perfil, nome ou usuário inválido.')
    if uid==user['id'] and (not data.active or data.role!='administrador'): raise HTTPException(400,'Não é permitido desativar ou rebaixar o próprio usuário administrador.')
    try:
        with transaction() as c:
            old=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
            if not old: raise HTTPException(404,'Usuário não encontrado.')
            if old['role']=='administrador' and old['active'] and (data.role!='administrador' or not data.active):
                active_admins=c.execute("SELECT COUNT(*) FROM users WHERE role='administrador' AND active=1").fetchone()[0]
                if active_admins<=1: raise HTTPException(409,'O sistema precisa manter pelo menos um administrador ativo.')
            if data.password:
                c.execute('UPDATE users SET username=?,name=?,role=?,active=?,password_hash=?,must_change_password=1 WHERE id=?',(username,name,data.role,int(data.active),pw_hash(data.password),uid))
                c.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
            else:
                c.execute('UPDATE users SET username=?,name=?,role=?,active=? WHERE id=?',(username,name,data.role,int(data.active),uid))
                if not data.active or data.role!=old['role']: c.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
            audit(c,user['id'],'alteracao','usuario',uid,username)
    except sqlite3.IntegrityError as e: raise HTTPException(409,'Nome de usuário já existe.') from e
    return {'ok':True}
@APP.delete('/api/users/{uid}')
def remove_user_two_steps(uid:int,user=Depends(allow('administrador'))):
    if uid==user['id']: raise HTTPException(400,'Não é permitido remover ou excluir o próprio usuário conectado.')
    with transaction() as c:
        target=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
        if not target: raise HTTPException(404,'Usuário não encontrado.')
        if target['active']:
            if target['role']=='administrador':
                active_admins=c.execute("SELECT COUNT(*) FROM users WHERE role='administrador' AND active=1").fetchone()[0]
                if active_admins<=1: raise HTTPException(409,'O sistema precisa manter pelo menos um administrador ativo.')
            c.execute('UPDATE users SET active=0 WHERE id=?',(uid,)); c.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
            audit(c,user['id'],'inativacao','usuario',uid,target['username'])
            return {'ok':True,'stage':'inativado','mensagem':'Usuário inativado. Clique novamente em Excluir definitivamente para removê-lo.'}
        if target['role']=='administrador':
            active_admins=c.execute("SELECT COUNT(*) FROM users WHERE role='administrador' AND active=1").fetchone()[0]
            if active_admins<1: raise HTTPException(409,'É necessário manter pelo menos um administrador ativo.')
        references={
            'vendas':c.execute('SELECT COUNT(*) FROM sales WHERE operator_id=?',(uid,)).fetchone()[0],
            'sessões de caixa':c.execute('SELECT COUNT(*) FROM cash_sessions WHERE user_id=?',(uid,)).fetchone()[0],
            'movimentações de caixa':c.execute('SELECT COUNT(*) FROM cash_movements WHERE user_id=?',(uid,)).fetchone()[0],
            'movimentações de estoque':c.execute('SELECT COUNT(*) FROM stock_movements WHERE user_id=?',(uid,)).fetchone()[0],
            'pagamentos de fiado':c.execute('SELECT COUNT(*) FROM credit_settlements WHERE operator_id=?',(uid,)).fetchone()[0],
            'cancelamentos':c.execute('SELECT COUNT(*) FROM sales WHERE canceled_by=?',(uid,)).fetchone()[0],
        }
        used=[label for label,count in references.items() if count]
        if used: raise HTTPException(409,'O usuário permanece inativo, mas não pode ser excluído porque já possui histórico: '+', '.join(used)+'.')
        c.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
        c.execute('UPDATE audit_logs SET user_id=NULL WHERE user_id=?',(uid,))
        c.execute('UPDATE credit_customers SET created_by=NULL WHERE created_by=?',(uid,))
        audit(c,user['id'],'exclusao_definitiva','usuario',uid,target['username'])
        c.execute('DELETE FROM users WHERE id=?',(uid,))
    return {'ok':True,'stage':'excluido','mensagem':'Usuário excluído definitivamente.'}

@APP.get('/api/audit')
def audit_history(limit:int=300,date:str='',usuario:str='',action:str='',user=Depends(allow('administrador'))):
    clauses=[]; args=[]
    if date.strip():
        value=date.strip()
        try:
            if '/' in value: value=datetime.strptime(value,'%d/%m/%Y').date().isoformat()
            else: value=datetime.strptime(value,'%Y-%m-%d').date().isoformat()
        except ValueError: raise HTTPException(400,'Data inválida; use AAAA-MM-DD ou DD/MM/AAAA.')
        clauses.append('substr(a.created_at,1,10)=?'); args.append(value)
    if usuario.strip():
        clauses.append("(COALESCE(u.name,'Sistema') LIKE ? OR COALESCE(u.username,'') LIKE ?)"); args.extend([f'%{usuario.strip()}%',f'%{usuario.strip()}%'])
    if action.strip(): clauses.append('(a.action LIKE ? OR a.details LIKE ?)'); args.extend([f'%{action.strip()}%',f'%{action.strip()}%'])
    where=(' WHERE '+' AND '.join(clauses)) if clauses else ''
    c=connect(); rows=[dict(r) for r in c.execute("SELECT a.id,a.action,a.entity,a.entity_id,a.details,a.created_at,COALESCE(NULLIF(a.actor_username,''),u.username,'') username,COALESCE(NULLIF(a.actor_name,''),u.name,'Sistema') name FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id"+where+' ORDER BY a.id DESC LIMIT ?',(*args,min(max(limit,1),1000)))]; c.close(); return rows

@APP.get('/api/audit/{audit_id}')
def audit_detail(audit_id:int,user=Depends(allow('administrador'))):
    c=connect(); row=c.execute("SELECT a.id,a.action,a.entity,a.entity_id,a.details,a.created_at,COALESCE(NULLIF(a.actor_username,''),u.username,'') username,COALESCE(NULLIF(a.actor_name,''),u.name,'Sistema') name,a.before_json,a.after_json FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id WHERE a.id=?",(audit_id,)).fetchone(); c.close()
    if not row: raise HTTPException(404,'Registro de auditoria não encontrado.')
    result=dict(row)
    for column,target in (('before_json','before_data'),('after_json','after_data')):
        try: result[target]=json.loads(result[column]) if result[column] else None
        except (TypeError,ValueError): result[target]=None
        result.pop(column,None)
    return result

@APP.get('/')
def index(): return FileResponse(ROOT/'static'/'index.html')
APP.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')
