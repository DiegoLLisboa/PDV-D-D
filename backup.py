from datetime import datetime
from pathlib import Path
import sqlite3, sys
from app import DATA_DIR, DB
ROOT=Path(__file__).resolve().parent
out=Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'backups'
out.mkdir(parents=True,exist_ok=True)
if not DB.exists(): raise SystemExit(f'Banco não encontrado: {DB}')
target=out/(f'pdv-{datetime.now().strftime("%Y%m%d-%H%M%S")}.sqlite3' if out.is_dir() else out)
with sqlite3.connect(DB) as src, sqlite3.connect(target) as dst:
    src.backup(dst)
    result=dst.execute('PRAGMA integrity_check').fetchone()[0]
if result!='ok': target.unlink(missing_ok=True); raise SystemExit(f'Backup inválido: {result}')
print(f'Backup validado: {target}')
