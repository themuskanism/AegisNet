import os
from alembic import context
from sqlalchemy import engine_from_config,pool
from backend.store import Base
config=context.config
url=os.environ.get('AEGIS_DATABASE_URL',config.get_main_option('sqlalchemy.url'))
if context.is_offline_mode():
    context.configure(url=url,target_metadata=Base.metadata,literal_binds=True)
    with context.begin_transaction():context.run_migrations()
else:
    settings=config.get_section(config.config_ini_section);settings['sqlalchemy.url']=url
    engine=engine_from_config(settings,prefix='sqlalchemy.',poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection,target_metadata=Base.metadata)
        with context.begin_transaction():context.run_migrations()
