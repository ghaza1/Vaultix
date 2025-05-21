# File: run_migrations.py
import os
from flask_migrate import upgrade as alembic_upgrade
from alembic.config import Config as AlembicConfig

# You MUST import your Flask 'app' and 'db' instances here
# This assumes your main Flask app instance is named 'app' in 'app.py'
# and your SQLAlchemy instance is named 'db' in 'app.py'.
# Adjust the import according to your project structure.
from app import app, db # Or from your_package import app, db

def apply_migrations():
    """
    Applies database migrations to the 'head' (latest) revision.
    """
    with app.app_context():
        print("Attempting to apply database migrations (upgrade to head)...")
        try:
            # Construct the Alembic configuration path
            # Alembic usually expects alembic.ini to be in the 'migrations' directory
            # or for the script_location to be set relative to where alembic.ini is.
            # If your alembic.ini is in the root, adjust path.
            # Flask-Migrate typically sets up alembic.ini inside the 'migrations' folder.
            
            migrations_dir = os.path.join(os.path.dirname(__file__), 'migrations')
            ini_path = os.path.join(migrations_dir, 'alembic.ini')

            if not os.path.exists(ini_path):
                print(f"Error: alembic.ini not found at {ini_path}")
                print("Make sure Flask-Migrate has been initialized (flask db init) and alembic.ini is present.")
                return

            alembic_cfg = AlembicConfig(ini_path)
            
            # Flask-Migrate usually sets the script_location in alembic.ini
            # If not, or if running from a different CWD, you might need to set it:
            # alembic_cfg.set_main_option("script_location", migrations_dir)
            
            alembic_upgrade(directory=migrations_dir, revision='head')
            print("Migrations applied successfully (upgraded to head).")
        except Exception as e:
            print(f"An error occurred during migration upgrade: {e}")
            import traceback
            traceback.print_exc()

def generate_migration(message):
    """
    Generates a new migration script.
    Equivalent to 'flask db migrate -m "message"'
    """
    with app.app_context():
        print(f"Attempting to generate new migration: {message}")
        try:
            migrations_dir = os.path.join(os.path.dirname(__file__), 'migrations')
            ini_path = os.path.join(migrations_dir, 'alembic.ini')

            if not os.path.exists(ini_path):
                print(f"Error: alembic.ini not found at {ini_path}")
                return

            alembic_cfg = AlembicConfig(ini_path)
            # alembic_cfg.set_main_option("script_location", migrations_dir) # Usually set in alembic.ini

            from alembic import command as alembic_command
            alembic_command.revision(alembic_cfg, message=message, autogenerate=True)
            print(f"Migration script generated for: {message}")
        except Exception as e:
            print(f"An error occurred during migration generation: {e}")
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    # To generate a migration:
    # migration_message = "Sync with current DB state before adding salt_nonce"
    # print(f"Generating migration: {migration_message}")
    # generate_migration(migration_message)
    
    # To apply migrations:
    print("Applying migrations...")
    apply_migrations()