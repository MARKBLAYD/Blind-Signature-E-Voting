import psycopg2
from psycopg2 import sql
from datetime import datetime

#Функция подключения к клиентской БД
def connect_to_client_db(admin_password):
    """Подключение к клиентской базе данных."""
    return psycopg2.connect(
        dbname="Client_BD",
        user="postgres",
        password=admin_password,
        host="localhost",
        port="5432"
    )

#Функция создания клиентской БД и таблиц
def create_client_database_and_tables(admin_password):
    # 1. Подключение к серверу PostgreSQL
    conn = connect_to_client_db(admin_password)
    conn.autocommit = True
    cursor = conn.cursor()

    # 2. Создание базы данных
    db_name = "Client_BD"
    try:
        cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
        print(f"База данных '{db_name}' успешно создана.")
    except psycopg2.errors.DuplicateDatabase:
        print(f"База данных '{db_name}' уже существует.")

    cursor.close()
    conn.close()

    # 3. Подключаемся к новой БД
    conn = psycopg2.connect(
        dbname=db_name,
        user="postgres",
        password=admin_password,
        host="localhost",
        port="5432"
    )
    cursor = conn.cursor()

    # 4. Создание таблицы elections
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS elections (
        id SERIAL PRIMARY KEY,
        id_election_cik INTEGER NOT NULL,
        title TEXT NOT NULL,
        option_count INTEGER NOT NULL,
        public_key_cik BYTEA,
        public_key_my BYTEA,
        private_key_my BYTEA,
        date TIMESTAMP NOT NULL,
        metka BYTEA,
        closing_multiplier_r INTEGER,
        voting_b INTEGER,
        ds_cik_blind BYTEA
    );
    """)
    print("Таблица 'elections' успешно создана.")

    # 5. Создание таблицы voting_options
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS voting_options (
        id SERIAL PRIMARY KEY,
        election_id INTEGER NOT NULL,
        option_number INTEGER NOT NULL,
        option_text TEXT NOT NULL,
        result INTEGER
    );
    """)
    print("Таблица 'voting_options' успешно создана.")

    # 6. Завершение
    conn.commit()
    cursor.close()
    conn.close()

#определение статуса голосования
def determine_status(election, voting_options):
    public_key_my, public_key_cik, metka, ds_cik_blind = election[1:5]
    results_exist = any(v[1] is not None for v in voting_options)

    if results_exist:
        return "завершено"
    elif ds_cik_blind is not None:
        return "активное(участвовал, голос не отправлен)"
    elif metka is not None:
        return "активное(участвовал, ожидание слепой подписи)"
    elif public_key_cik is not None:
        return "активное(получен ключ ЦИК)"
    elif public_key_my is not None:
        return "активное(отправлен ключ ЦСК)"
    else:
        return "активное(не участвовал)"

#список голосований с формированием статуса
def get_all_client_elections(admin_password):
    conn = connect_to_client_db(admin_password)
    cursor = conn.cursor()
    cursor.execute("SELECT id, public_key_my, public_key_cik, metka, ds_cik_blind, date FROM Elections;")
    elections = cursor.fetchall()

    for election in elections:
        eid = election[0]
        cursor.execute("SELECT id, result FROM voting_options WHERE election_id = %s", (eid,))
        voting_opts = cursor.fetchall()
        status = determine_status(election[1:], voting_opts)
        print(f"id: {eid}, title: (не загружено, добавь выбор title), status: {status}, date: {election[5]}")

    cursor.close()
    conn.close()

#детальная информация по одному голосованию
def get_client_election_info(admin_password, election_id):
    conn = connect_to_client_db(admin_password)
    cursor = conn.cursor()
    cursor.execute("SELECT title, public_key_my, public_key_cik, metka, ds_cik_blind, option_count FROM Elections WHERE id = %s;", (election_id,))
    election = cursor.fetchone()

    cursor.execute("SELECT option_number, option_text FROM voting_options WHERE election_id = %s;", (election_id,))
    options = cursor.fetchall()

    cursor.execute("SELECT id, result FROM voting_options WHERE election_id = %s;", (election_id,))
    voting_opts = cursor.fetchall()
    status = determine_status(election[1:6], voting_opts)

    print(f"title: {election[0]}, status: {status}, option_count: {election[5]}")
    for opt in options:
        print(f"option_number: {opt[0]}, option_text: {opt[1]}")

    cursor.close()
    conn.close()

#удаление голосования и всех вариантов
def delete_client_election(admin_password, election_id):
    conn = connect_to_client_db(admin_password)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM voting_options WHERE election_id = %s;", (election_id,))
    cursor.execute("DELETE FROM Elections WHERE id = %s;", (election_id,))
    conn.commit()
    cursor.close()
    conn.close()

#добавление нового голосования
def create_client_election(admin_password, id_cik, title, option_count):
    conn = connect_to_client_db(admin_password)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO Elections (id_cik, title, option_count, date)
        VALUES (%s, %s, %s, %s)
        RETURNING id;
    """, (id_cik, title, option_count, datetime.now()))
    election_id = cursor.fetchone()[0]
    conn.commit()
    cursor.close()
    conn.close()
    return election_id

#добавление варианта голосования
def add_voting_option(admin_password, election_id, option_number, option_text):
    conn = connect_to_client_db(admin_password)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO voting_options (election_id, option_number, option_text)
        VALUES (%s, %s, %s);
    """, (election_id, option_number, option_text))
    conn.commit()
    cursor.close()
    conn.close()

#установка результата варианта
def set_voting_result(admin_password, option_id, result):
    conn = connect_to_client_db(admin_password)
    cursor = conn.cursor()
    cursor.execute("UPDATE voting_options SET result = %s WHERE id = %s;", (result, option_id))
    conn.commit()
    cursor.close()
    conn.close()

#сохранение своих ключей
def save_my_keys(admin_password, election_id, public_key_my, private_key_my):
    conn = connect_to_client_db(admin_password)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE Elections SET public_key_my = %s, private_key_my = %s WHERE id = %s;
    """, (public_key_my, private_key_my, election_id))
    conn.commit()
    cursor.close()
    conn.close()

#сохранение ключа ЦИК
def save_cik_key(admin_password, election_id, public_key_cik):
    conn = connect_to_client_db(admin_password)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE Elections SET public_key_cik = %s WHERE id = %s;
    """, (public_key_cik, election_id))
    conn.commit()
    cursor.close()
    conn.close()

#сохранение r и метки
def save_blinding_info(admin_password, election_id, r, metka):
    conn = connect_to_client_db(admin_password)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE Elections SET closing_multiplier_r = %s, metka = %s WHERE id = %s;
    """, (r, metka, election_id))
    conn.commit()
    cursor.close()
    conn.close()

#сохранение голоса и слепой подписи
def save_vote_and_signature(admin_password, election_id, voting_b, ds_cik_blind):
    conn = connect_to_client_db(admin_password)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE Elections SET voting_b = %s, ds_cik_blind = %s WHERE id = %s;
    """, (voting_b, ds_cik_blind, election_id))
    conn.commit()
    cursor.close()
    conn.close()
