"""Local-only launcher. Environment overrides optional .env; never prints secrets."""
import os
from pathlib import Path
import secrets
import uvicorn

def main():
    root=Path(__file__).resolve().parents[1];os.chdir(root)
    env=root/'.env'
    if env.exists():
        for line in env.read_text().splitlines():
            if '=' in line and not line.lstrip().startswith('#'):
                key,value=line.split('=',1)
                if key.strip().startswith('AEGIS_'):os.environ.setdefault(key.strip(),value.strip())
    token=root/'data/analyst-token.txt';token.parent.mkdir(exist_ok=True)
    if not os.environ.get('AEGIS_API_TOKEN'):
        if not token.exists():token.write_text(secrets.token_urlsafe(32))
        os.environ['AEGIS_API_TOKEN']=token.read_text().strip()
        print('Analyst token file:',token)
    if not os.environ.get('AEGIS_DATABASE_URL'):print('SQLite LOCAL TEST mode. Set AEGIS_DATABASE_URL for PostgreSQL deployment.')
    print('Dashboard: http://127.0.0.1:8000 — simulation default; capture initially stopped.')
    uvicorn.run('backend.api:app',host='127.0.0.1',port=8000,workers=1)

if __name__=='__main__':main()
