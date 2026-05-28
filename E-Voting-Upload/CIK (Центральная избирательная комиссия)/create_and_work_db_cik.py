import psycopg2
from psycopg2 import sql

def connect_to_cik_db(admin_password):
    """Подключение к базе данных ЦИК."""
    return psycopg2.connect(
        dbname="CIK_BD",
        user="postgres",
        password=admin_password,
        host="localhost",
        port="5432"
    )

def create_csk_database_and_tables(admin_password):
    # 1. Подключаемся к серверу PostgreSQL (стартуем с дефолтной БД)
    conn = psycopg2.connect(
        dbname="postgres",
        user="postgres",
        password=admin_password,
        host="localhost",
        port="5432"
    )
    conn.autocommit = True
    cursor = conn.cursor()

    db_name = "CIK_BD"

    # 2. Создаём базу данных CSK_BD
    try:
        cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
        print(f"База данных '{db_name}' успешно создана.")
    except psycopg2.errors.DuplicateDatabase:
        print(f"База данных '{db_name}' уже существует.")

    cursor.close()
    conn.close()

    # 3. Подключаемся к новосозданной БД
    conn = psycopg2.connect(
        dbname=db_name,
        user="postgres",
        password=admin_password,
        host="localhost",
        port="5432"
    )
    cursor = conn.cursor()

    # 4. Таблица elections
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS elections (
        id SERIAL PRIMARY KEY,
        title TEXT,
        option_count INTEGER,
        date_create TIMESTAMP,
        date_active TIMESTAMP,
        date_completion TIMESTAMP,
        public_key BYTEA,
        private_key BYTEA
    );
    """)
    print("Таблица 'elections' успешно создана.")

    # 5. Таблица election_options
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS election_options (
        id SERIAL PRIMARY KEY,
        id_election INTEGER,
        option_number INTEGER,
        option_text TEXT,
        result INTEGER
    );
    """)
    print("Таблица 'election_options' успешно создана.")

    # 6. Таблица client
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS client (
        id SERIAL PRIMARY KEY,
        name TEXT,
        date TIMESTAMP
    );
    """)
    print("Таблица 'client' успешно создана.")

    # 7. Таблица voice
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS voice (
        id SERIAL PRIMARY KEY,
        id_client INTEGER,
        key_public_client BYTEA,
        id_election INTEGER,
        ds_client_blind BYTEA,
        m_client_blind BYTEA,
        date TIMESTAMP
    );
    """)
    print("Таблица 'voice' успешно создана.")

    # 8. Таблица bilutens
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS bilutens (
        id SERIAL PRIMARY KEY,
        ds BYTEA,
        m BYTEA,
        b INTEGER,
        date TIMESTAMP
    );
    """)
    print("Таблица 'bilutens' успешно создана.")

    # 9. Завершаем работу
    conn.commit()
    cursor.close()
    conn.close()
