from sqlalchemy import create_engine, text
from app.config import settings

# Use the existing settings to find the DB
DATABASE_URL = settings.DATABASE_URL
engine = create_engine(DATABASE_URL)

with engine.connect() as connection:
    result = connection.execute(text("SELECT id, email, full_name, current_role_title FROM users"))
    print("\n--- USERS IN DATABASE ---")
    for row in result:
        print(f"ID: {row[0]}, Email: '{row[1]}', Name: {row[2]}")
    print("-------------------------\n")
