from getpass import getpass
from app import DB, audit, connect, now, pw_hash, transaction

username=input('Usuário administrador [admin]: ').strip() or 'admin'
with connect() as c:
    user=c.execute("SELECT id,name FROM users WHERE username=? AND role='administrador'",(username,)).fetchone()
if not user:
    raise SystemExit(f'Não encontrei uma conta administradora com o usuário {username!r} no banco {DB}.')
new=getpass('Digite a nova senha (pelo menos 1 caractere): ')
confirm=getpass('Confirme a nova senha: ')
if len(new)<1:
    raise SystemExit('A senha precisa ter pelo menos 1 caractere.')
if new!=confirm:
    raise SystemExit('As senhas não conferem; nenhuma alteração foi feita.')
with transaction() as c:
    c.execute('UPDATE users SET password_hash=? WHERE id=?',(pw_hash(new),user['id']))
    c.execute('DELETE FROM sessions WHERE user_id=?',(user['id'],))
    audit(c,user['id'],'redefinicao_senha','usuario',user['id'],'Redefinição local pelo administrador')
print(f'Senha redefinida para {username!r}. Sessões anteriores encerradas. Banco: {DB}')
print('Reinicie o PDV e entre com a senha nova. A senha não foi exibida nem salva em arquivo.')
