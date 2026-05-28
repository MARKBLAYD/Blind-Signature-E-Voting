import psycopg2
from psycopg2 import sql
import os
from datetime import datetime


#Подключение к базе данных
def connect_to_db(admin_password):
    """Подключение к базе данных."""
    return psycopg2.connect(
        dbname="CSK_BD",
        user="postgres",
        password=admin_password,
        host="localhost",
        port="5432"
    )


def create_database_and_tables(admin_password):
    # 1. Устанавливаем соединение с PostgreSQL сервером для создания новой БД
    conn = psycopg2.connect(
        dbname="postgres",  # Подключаемся к базе данных по умолчанию
        user="postgres",  # Главный пользователь
        password=admin_password,  # Пароль для главного пользователя
        host="localhost",  # Локальный хост
        port="5432"  # Порт по умолчанию для PostgreSQL
    )
    
    conn.autocommit = True  # Для выполнения CREATE DATABASE без транзакции
    cursor = conn.cursor()
    
    # 2. Создаём новую базу данных в указанной папке
    db_name = "CSK_BD"
    try:
        cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
        print(f"База данных '{db_name}' успешно создана.")
    except psycopg2.errors.DuplicateDatabase:
        print(f"База данных '{db_name}' уже существует.")
    
    cursor.close()
    conn.close()
    
    # 3. Подключаемся к новой базе данных
    conn = connect_to_db(admin_password)
    cursor = conn.cursor()
    
    # 4. Создаём таблицу election
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS election (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        id_election_cik INT NOT NULL,
        sending BOOLEAN NOT NULL,
        date TIMESTAMP NOT NULL
    );
    """)
    print("Таблица 'election' успешно создана.")

    # 5. Создаём таблицу key_public
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS key_public (
        id SERIAL PRIMARY KEY,
        id_client TEXT NOT NULL,
        name TEXT NOT NULL,
        key_pub BYTEA,
        id_election INT NOT NULL,
        date TIMESTAMP
    );
    """)
    print("Таблица 'key_public' успешно создана.")

    # 6. Закрываем соединение
    conn.commit()  # Подтверждаем изменения
    cursor.close()
    conn.close()
