"""Exercise migrations only in a newly created disposable database, never the configured DB."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url
from backend.store import Store
from backend.response import ResponseService

def main():
    configured=make_url(os.environ['AEGIS_DATABASE_URL'])
    temporary='aegis_verify_'+uuid.uuid4().hex[:12]
    admin=configured.set(drivername='postgresql',database='postgres').render_as_string(hide_password=False)
    target=configured.set(database=temporary).render_as_string(hide_password=False)
    with psycopg.connect(admin,autocommit=True) as connection:
        version=connection.execute('SHOW server_version').fetchone()[0]
        connection.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(temporary)))
        try:
            env={**os.environ,'AEGIS_DATABASE_URL':target}
            for command in [('upgrade','head'),('downgrade','base'),('upgrade','head')]:
                subprocess.run([sys.executable,'-m','alembic',*command],env=env,check=True,capture_output=True)
            store=Store(target);assert store.health()['status']=='ready'
            action=ResponseService(store).request('block','8.8.4.4','Disposable PostgreSQL verification','MANUAL')
            store.engine.dispose()
            restarted=Store(target);assert restarted.actions()[0]['id']==action['id']
            service=ResponseService(restarted);assert service.decide(action['id'],True)['status']=='simulated'
            assert service.decide(action['id'],True)['status']=='simulated'
            assert restarted.list_sources('blocked')==[]
            restarted.engine.dispose()
            result={'verified_at':time.time(),'postgres_version':version,'migration_upgrade_downgrade_upgrade':'passed','new_connection_persistence':'passed','manual_approval_idempotency':'passed','scope':'new disposable database; existing database untouched'}
            Path('artifacts/postgres_verification.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
        finally:
            # Identifier generated above in this invocation, never from user-supplied database name.
            connection.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(temporary)))

if __name__=='__main__':main()
