import os

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode, b64decode
import hashlib
import psycopg2
from psycopg2 import sql
import random
from datetime import datetime
import string
from pathlib import Path


# --- Подпись слепой метки Mbl ---
def sign_message_blinded(priv_key_der: bytes, message_bytes: bytes) -> bytes:
    key = import_rsa_key(priv_key_der)
    h = SHA256.new(message_bytes)
    return pkcs1_15.new(key).sign(h)


# --- Расшифровка бюллетеня ---
def decrypt_ballot(priv_key_der: bytes, encrypted: bytes):
    key = import_rsa_key(priv_key_der)
    cipher = PKCS1_OAEP.new(key)
    ballot = json.loads(cipher.decrypt(encrypted).decode())
    return {
        "M": bytes.fromhex(ballot["M"]),
        "DS": bytes.fromhex(ballot["DS"]),
        "B": ballot["B"]
    }


# --- Проверка подписи ---
def verify_signature(pub_key_der: bytes, signature: bytes, message_bytes: bytes) -> bool:
    key = import_rsa_key(pub_key_der)
    h = SHA256.new(message_bytes)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# Генерация RSA ключей
def generate_rsa_key_pair(bits=2048):
    key = RSA.generate(bits)
    return key.publickey().export_key(format='DER'), key.export_key(format='DER')  # BYTEA


def bytes_to_psql_bytea(data: bytes):
    """Готовит данные для вставки в поле BYTEA PostgreSQL."""
    return psycopg2.Binary(data)


def psql_bytea_to_bytes(bytea_field) -> bytes:
    """При извлечении BYTEA из базы он уже bytes, но эта функция — для ясности."""
    return bytes(bytea_field)


#Результат голосования
def created_res_client_messgae(file_path, title, id_election, option_count, data_nember_text_result, count_mb, data_mb):
    data = {
        "title": title,
        "id_election": id_election,
        "date": str(datetime.now()),
        "option_count": option_count,
        "data_nember_text_result": data_nember_text_result,
        "count_mb": count_mb,
        "data_mb": data_mb
    }
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f)
        return True
    except:
        return False


#Регистрация пользователя
def created_start_client_message(file_path, name, id_client)
    data = {
        "name": title,
        "id_client": id_election,
        "date": str(datetime.now()),
    }
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f)
        return True
    except:
        return False


  #"""Генерирует случайную строку с 5-значным числом."""


#Приглашение на голосование
def created_reg_client_message(file_path, title, id_election, count_number, data_number_text):
    data = {
        "title": title,
        "id_election": id_election,
        "date": str(datetime.now()),
        "count_number": count_number,
        "data_number_text": data_number_text
    }
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f)
        return True
    except:
        return False


#Слепая подпись для голосования
def created_ds_client_messgae(file_path, name, id_client, id_election, ds_cik_blind):
    data = {
        "name": name,
        "id_client": id_client,
        "date": str(datetime.now()),
        "id_election": id_election,
        "ds_cik_blind": ds_cik_blind
    }
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f)
        return True
    except:
        return False


#Добавление/обновление ключа и голосования для ЦСК================================
def created_csk_message(file_path, title, id_election, key_csk, count_name, data_name_id):
    data = {
        "title": title,
        "id_election": id_election,
        "date": str(datetime.now()),
        "key_csk": key_csk,
        "count_name": count_name,
        "data_name_id": data_name_id
    }
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f)
        return True
    except:
        return False


#Ответ от ЦСК
def read_csk_message(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["id_election"], data["date"], data["count_key"], data["data_key"]


#Скрытая метка
def read_blind_client_messgae(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["id_client"], data["id_election"], data["date"], data["m_blind"], data["ds_client_blind"]


#Голос
def read_vot_cik_messgae(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["id_election"], data["date"], data["encrypted_data"]


def gen_salt():
  return str(random.randint(10000, 99999))


# Функция очистки консоли
def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')


def wait_for_user():
    input("\nНажмите любую клавишу, чтобы продолжить...")


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
    conn = connect_to_cik_db(admin_password)
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
        id_election INTEGER,
        date TIMESTAMP
    );
    """)
    print("Таблица 'bilutens' успешно создана.")

    # 9. Завершаем работу
    conn.commit()
    cursor.close()
    conn.close()


# Функция для создания ключа из пароля
def generate_key(password: str):
    # Соль для генерации ключа
    salt = b"random_salt"  # Можно использовать произвольную соль
    # Генерация ключа с помощью PBKDF2 (Password-Based Key Derivation Function 2)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# Функция для шифрования данных
def encrypt_data(password, data):
    key = generate_key(password)
    iv = os.urandom(16)  # Инициализирующий вектор для AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Преобразование данных в формат json
    json_data = json.dumps(data).encode()
    padding = 16 - len(json_data) % 16
    json_data += bytes([padding]) * padding  # Паддинг данных до размера блока AES

    encrypted_data = encryptor.update(json_data) + encryptor.finalize()
    return b64encode(iv + encrypted_data).decode()


# Функция для дешифрования данных
def decrypt_data(password, encrypted_data):
    key = generate_key(password)
    data = b64decode(encrypted_data)
    iv = data[:16]  # Извлечение инициализирующего вектора
    encrypted_data = data[16:]  # Извлечение зашифрованных данных
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    padding = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding]
    return json.loads(decrypted_data.decode())


def check_db_password(password):
    try:
        conn = psycopg2.connect(
            dbname="postgres",  # Можно использовать служебную БД по умолчанию
            user="postgres",
            password=password,
            host="localhost",
            port="5432"
        )
        conn.close()
        return True
    except psycopg2.OperationalError as e:
        return False


# Функция для работы с файлом
def handle_password():
    # Проверка, существует ли файл с данными
    clear_console()
    if os.path.exists("kesh_cik.txt"):
        for _ in range(3):
            clear_console()
            password = input("Введите пароль для входа в приложение: ")
            try:
                # Попытка дешифровать данные
                with open("kesh_cik.txt", "r") as f:
                    encrypted_data = f.read()
                    data = decrypt_data(password, encrypted_data)
                    return data
            except Exception as e:
                print("Неверный пароль. Попробуйте снова.")
        print("Пароль введен неправильно 3 раза.")
        wait_for_user()
        return None
    else:
        clear_console()
        print("Приложение не активировано")
        password = input("Придумайте пароль для входа в приложение: ")
        data = []
        while True:
            chice=input("Введите пароль для работы с psql:")
            if !check_db_password(chice):
                print("Пароль не подходит для подключения к psql, введите корректный пароль")
        data.append(chice)
        create_database_and_tables(data[0])
        # Шифрование и запись в файл
        encrypted_data = encrypt_data(password, data)
        with open("kesh_cik.txt", "w") as f:
            f.write(encrypted_data)
        nested_folder_path = os.path.join("sent_message","CIK")
        os.makedirs(nested_folder_path, exist_ok=True)
        nested_folder_path = os.path.join("read_message")
        os.makedirs(nested_folder_path, exist_ok=True)
        print("Приложение активировано")
        wait_for_user()
        return data


def read_message(admin_password):
    # Указываем папку, где хранятся сообщения
    message_folder = Path('read_message')
    clear_console()
    # Спрашиваем пользователя, хочет ли он автоматическую обработку или ручную
    mode = input("Вы хотите проверить все файлы вручную или автоматически? (1-ручной/2-автоматический): ").strip().lower()
    
    # Проверяем все файлы по порядку
    if mode not in ['1', '2']:
        print("Некорректный выбор.")
        wait_for_user()
        return
    
    files = sorted(message_folder.glob('*.txt'))  # Считываем все .txt файлы в папке
    
    cik_key_files = [file for file in files if file.name.startswith("cik_key_csk_")]
    hidden_label_files = [file for file in files if '_hidden_label_' in file.name]
    voting_files = [file for file in files if file.name.startswith("voting_")]
    
    # Автоматическая обработка (если выбрано)
    if mode == '1':
        k=process_cik_key_files(cik_key_files, mode)
        k=process_hidden_label_files(hidden_label_files, mode, admin_password)
        process_voting_files(voting_files, mode, admin_password)
    else:
        # Ручной режим
        for file in cik_key_files:
            k=process_cik_key_files(file, mode, admin_password)
            if k==1:
                return
        
        for file in hidden_label_files:
            k=process_hidden_label_files(file, mode, admin_password)
            if k==1:
                return
        
        for file in voting_files:
            process_voting_files(file, mode, admin_password)


def process_cik_key_files(files, mode, admin_password):
    #"""Обрабатывает файлы cik_key_csk_*.txt"""
    for file in files:
        clear_console()
        id_election, date, count_key, data_key = read_csk_message(file)
        print(f"От ЦСК получены ключи для голосования. ID голосования: {id_election}, Дата: {date}, Количество ключей: {count_key}")
        
        # Получаем информацию о голосовании
        # Подключаемся к БД, получаем данные
        conn = connect_to_cik_db(admin_password)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, title 
            FROM elections 
            WHERE id = %s;
        """, (id_election,))
        election = cursor.fetchone()
        if election:
            print(f"Информация о голосовании: ID = {election[0]}, Title = {election[1]}")
            if mode =='1':
                action ='1'
            else:
                action = input("Что сделать? 1 - Добавить ключи, 2 - Не добавлять (удалить файл), 3 - Рассмотреть позже, 4 - Перейти к следующему типу сообщений, 5 - Выйти: ").strip()
            if action == '1':
                for i in range(count_key):
                    key_data = data_key["key"][i]
                    id_client = data_key["id_client"][i]
                    # Добавляем ключи в таблицу voice
                    cursor.execute("""
                        UPDATE voice 
                        SET key_public_client = %s 
                        WHERE id_client = %s AND id_election = %s;
                    """, (bytes_to_psql_bytea(key_data), id_client, id_election))
                conn.commit()
                print("Ключи добавлены.")
                wait_for_user()
                activated_election(election_id)
            elif action == '2':
                os.remove(file)
                print(f"Файл {file.name} удален.")
                wait_for_user()
            elif action == '3':
                continue
            elif action == '4':
                conn.rollback()
                cursor.close()
                conn.close()
                return 0
            elif action == '5':
                conn.rollback()
                cursor.close()
                conn.close()
                return 1
        cursor.close()
        conn.close()
        return 0


#функция активации выборов
def activated_election(admin_password, election_id):
    # 1. Записываем текущую дату в поле date_active в таблице elections
    current_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("""
        UPDATE elections
        SET date_active = %s
        WHERE id = %s;
    """, (current_date, election_id))
    conn.commit()

    # 2. Извлекаем title и option_count из таблицы elections
    cursor.execute("""
        SELECT title, option_count
        FROM elections
        WHERE id = %s;
    """, (election_id,))
    election_data = cursor.fetchone()

    if not election_data:
        print(f"Выборы с id {election_id} не найдены.")
        wait_for_user()
        return

    title, count_number = election_data
    print(f"Выборы активированы. Название: {title}, Количество вариантов: {count_number}")
    wait_for_user()


def process_hidden_label_files(files, mode, admin_password):
    """Обрабатывает файлы *_hidden_label_*.txt"""
    for file in files:
        clear_console()
        id_client, id_election, date, m_blind, ds_client_blind = read_blind_client_messgae(file)
        print(f"От клиента (ID: {id_client}) получена слепая метка для голосования. ID голосования: {id_election}, Дата: {date}")
        
        # Получаем информацию о голосовании и клиенте
        conn = connect_to_cik_db(admin_password)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, title, private_key  
            FROM elections 
            WHERE id = %s;
        """, (id_election,))
        election = cursor.fetchone()
        
        cursor.execute("""
            SELECT name 
            FROM client 
            WHERE id = %s;
        """, (id_client,))
        client = cursor.fetchone()
        
        if election and client:
            print(f"Информация о голосовании: ID = {election[0]}, Title = {election[1]}")
            print(f"Информация о клиенте: Name = {client[0]}")
            if mode =='1':
                action ='1'
            else
                action = input("Что сделать? 1 - Проверить подпись, 2 - Отклонить слепую метку (удалить файл), 3 - Рассмотреть позже, 4 - Перейти к следующему типу сообщений, 5 - Выйти: ").strip()
            if action == '1':
                cursor.execute("""
                    SELECT key_public_client 
                    FROM voice 
                    WHERE id = %s AND id_election = %s;
                """, (id_client, id_election))
                pub_key_der = psql_bytea_to_bytes(cursor.fetchone())
                signature_valid = verify_signature(pub_key_der, ds_client_blind, m_blind)
                if not signature_valid:
                    os.remove(file)
                    print(f"Файл {file.name} удален (неверная подпись).")
                    wait_for_user()
                else:
                    if mode =='1':
                        sign_action ='1'
                    else:
                        sign_action = input("Подписать слепую метку? 1 - Да, 2 - Нет: ").strip()
                    if sign_action == '1':
                        priv_key_der = psql_bytea_to_bytes(election[2])
                        ds_cik_blind = sign_message_blinded(priv_key_der, m_blind)
                        # Записываем данные в базу
                        cursor.execute("""
                            UPDATE voice 
                            SET ds_client_blind = %s, m_client_blind = %s 
                            WHERE id_client = %s AND id_election = %s;
                        """, (bytes_to_psql_bytea(ds_client_blind), bytes_to_psql_bytea(m_blind), id_client, id_election))
                        conn.commit()
                        # Создаем файл с подписью и отправляем
                        created_ds_client_messgae(f"sent_message/{client[0]}/{client[0]}_blind_signature_{gen_salt()}.txt", client[0], id_client, id_election, ds_cik_blind)
                    else:
                        os.remove(file)
                        print(f"Файл {file.name} удален (не подписан).")
                        wait_for_user()
            elif action == '2':
                os.remove(file)
                print(f"Файл {file.name} удален.")
                wait_for_user()
            elif action == '3':
                continue
            elif action == '4':
                conn.rollback()
                cursor.close()
                conn.close()
                return 0
            elif action == '5':
                conn.rollback()
                cursor.close()
                conn.close()
                return 1
        cursor.close()
        conn.close()


def process_voting_files(files, mode, admin_password):
    #"""Обрабатывает файлы voting_*.txt"""
    for file in files:
        clear_console()
        id_election, date, encrypted_data = read_vot_cik_messgae(file)
        print(f"Получен белютень для голосования. ID голосования: {id_election}, Дата: {date}")
        
        # Получаем информацию о голосовании
        conn = connect_to_cik_db(admin_password)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, title, private_key, public_key
            FROM elections 
            WHERE id = %s;
        """, (id_election,))
        election = cursor.fetchone()
        
        if election:
            print(f"Информация о голосовании: ID = {election[0]}, Title = {election[1]}")
            if mode =='1':
                action ='1'
            else:
                action = input("Что сделать? 1 - Обработать белютень, 2 - Отклонить белютень (удалить файл), 3 - Рассмотреть позже, 4 - Выйти: ").strip()
            if action == '1':
                priv_key_der = psql_bytea_to_bytes(election[2])
                decrypted_data = decrypt_ballot(priv_key_der, encrypted_data)
                signature_valid = verify_signature(psql_bytea_to_bytes(election[3]), decrypted_data["DS"], decrypted_data["M"])
                if signature_valid:
                    # Записываем в таблицу bilutens
                    cursor.execute("""
                        INSERT INTO bilutens (ds, m, b, id_election, date) 
                        VALUES (%s, %s, %s, %s, %s);
                    """, (
                        bytes_to_psql_bytea(decrypted_data["DS"]), 
                        bytes_to_psql_bytea(decrypted_data["M"]), 
                        decrypted_data["B"], 
                        id_election, 
                        datetime.now()
                    ))
                    conn.commit()
                    print("Белютень обработан и сохранен.")
                    wait_for_user()
                else:
                    os.remove(file)
                    print(f"Файл {file.name} удален (неверная подпись).")
                    wait_for_user()
            elif action == '2':
                os.remove(file)
                print(f"Файл {file.name} удален.")
                wait_for_user()
            elif action == '3':
                continue
            elif action == '4':
                conn.rollback()
                cursor.close()
                conn.close()
                return
        cursor.close()
        conn.close()


def menu_bd(admin_password):
    while True:
        clear_console()
        print("Что вы хотите сделать?\n")
        print("1 - Создать голосование")
        print("2 - Редактировать голосование")
        print("3 - Запущенные голосования")
        print("4 - Завершенные голосования")
        print("5 - Назад в меню")

        choice = input("\nВведите ваш выбор: ").strip()

        if choice == "1":
            created_election(admin_password)  # Вызов функции создания голосования
        elif choice == "2":
            work_election(admin_password)  # Вызов функции редактирования голосования
        elif choice == "3":
            active_election(admin_password)  # Вызов функции редактирования голосования
        elif choice == "4":
            endent_election(admin_password)  # Вызов функции завершенных голосований
        elif choice == "5":
            return  # Завершаем функцию и выходим в главное меню
        else:
            print("Некорректный выбор. Попробуйте снова.")
            wait_for_user()


def created_election(admin_password):
    conn = connect_to_cik_db(admin_password)
    cursor = conn.cursor()

    try:
        # Шаг 1. Ввод данных для голосования
        clear_console()
        print("Создание нового голосования:")

        title = input("Введите вопрос голосования (title): ").strip()
        option_count = int(input("Введите количество вариантов ответа: ").strip())
        date_create = datetime.now()

        # Шаг 2. Генерация ключей
        public_key, private_key = generate_rsa_key_pair()

        # Вставка данных о голосовании в таблицу elections
        cursor.execute("""
            INSERT INTO elections (title, option_count, date_create, date_active, date_completion, public_key, private_key)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id;
        """, (title, option_count, date_create, None, None, bytes_to_psql_bytea(public_key), bytes_to_psql_bytea(private_key)))

        election_id = cursor.fetchone()[0]
        print(f"\nГолосование '{title}' успешно создано с ID {election_id}.")

        # Шаг 3. Ввод вариантов ответов
        for i in range(option_count):
            print(f"\nВведите текст для варианта {i+1}:")
            option_text = input("Текст ответа: ").strip()

            # Вставка вариантов в таблицу election_options
            cursor.execute("""
                INSERT INTO election_options (id_election, option_number, option_text, result)
                VALUES (%s, %s, %s, %s);
            """, (election_id, i+1, option_text, None))

        # Шаг 5. Добавить пользователей к голосованию сразу?
        activate = input("\nДобавить пользователей к голосованию? (1-y/2-n): ").strip().lower()

        if activate == '1':
            add_client(admin_password, election_id)

        # Завершаем работу с БД
        conn.commit()
        cursor.close()
        conn.close()

    except Exception as e:
        print(f"Ошибка при создании голосования: {e}")
        conn.rollback()
        cursor.close()
        conn.close()


#"""Удаляет голосование и все связанные данные из базы данных."""
def delete_election(election_id):
    # 1. Удаление всех голосов, связанных с данным голосованием
    cursor.execute("""
        DELETE FROM voice 
        WHERE id_election = %s;
    """, (election_id,))

    # 2. Удаление всех вариантов ответов, связанных с этим голосованием
    cursor.execute("""
        DELETE FROM election_options 
        WHERE id_election = %s;
    """, (election_id,))

    # 3. Удаление всех билютеней, связанных с этим голосованием
    cursor.execute("""
        DELETE FROM bilutens 
        WHERE id_election = %s;
    """, (election_id,))

    # 4. Удаление самого голосования из таблицы elections
    cursor.execute("""
        DELETE FROM elections 
        WHERE id = %s;
    """, (election_id,))
    print(f"Голосование с ID {election_id} успешно удалено.")

    # Фиксируем изменения в базе данных
    conn.commit()


    #"""Добавить участника в голосование."""


def add_client(election_id):
    while True:
        clear_console()
        # Получаем список всех пользователей, которые уже участвуют в голосовании
        cursor.execute("""
            SELECT id, name
            FROM client
            WHERE id_election = %s;
        """, (election_id,))
        clients = cursor.fetchall()
        if clients:
            print("Список участников из системы:")
            for client in clients:
                print(f"ID: {client[0]}, Name: {client[1]}")
        else:
            print("Нет участников в система.")
            wait_for_user()
            return

        cursor.execute("""
            SELECT client.id, client.name
            FROM client
            JOIN voice ON client.id = voice.id_client
            WHERE voice.id_election = %s;
        """, (election_id,))
        clients = cursor.fetchall()

        if clients:
            print("Список участников, уже состоящих в голосовании:")
            for client in clients:
                print(f"ID: {client[0]}, Name: {client[1]}")
        else:
            print("Нет участников в голосовании.")

        # Просим ввести ID пользователей, которых нужно добавить
        ids = input("Введите ID пользователей через запятую, чтобы добавить их в голосование, или 'exit' для выхода: ")
        if ids.lower() == 'exit':
            return

        # Разбираем введенные ID
        try:
            ids = [int(id.strip()) for id in ids.split(',')]
        except ValueError:
            print("Неверный формат ввода. Попробуйте снова.")
            wait_for_user()
            continue

        # Добавляем участников в голосование
        for client_id in ids:
            # Проверяем, существует ли такой клиент
            cursor.execute("SELECT id FROM client WHERE id = %s;", (client_id,))
            if cursor.fetchone():
                cursor.execute("""
                    INSERT INTO voice (id_client, id_election, key_public_client, ds_client_blind, m_client_blind, date)
                    VALUES (%s, %s, NULL, NULL, NULL, %s);
                """, (client_id, election_id, datetime.now()))
                print(f"Клиент с ID {client_id} добавлен в голосование.")
            else:
                print(f"Клиент с ID {client_id} не существует. Пропущен.")
            
        # Фиксируем изменения
        conn.commit()

#"""Удалить участника из голосования."""
def delete_client(admin_password, election_id):
    while True:
        # Получаем список всех пользователей, которые участвуют в голосовании
        cursor.execute("""
            SELECT client.id, client.name
            FROM client
            JOIN voice ON client.id = voice.id_client
            WHERE voice.id_election = %s;
        """, (election_id,))
        clients = cursor.fetchall()

        if clients:
            print("Список участников, состоящих в голосовании:")
            for client in clients:
                print(f"ID: {client[0]}, Name: {client[1]}")
        else:
            print("Нет участников в голосовании.")
            wait_for_user()
            return

        # Просим ввести ID пользователей, которых нужно удалить
        ids = input("Введите ID пользователей через запятую, чтобы удалить их из голосования, или 'q' для выхода: ")
        if ids.lower() == 'q':
            return

        # Разбираем введенные ID
        try:
            ids = [int(id.strip()) for id in ids.split(',')]
        except ValueError:
            print("Неверный формат ввода. Попробуйте снова.")
            wait_for_user()
            continue

        # Удаляем участников из голосования
        for client_id in ids:
            # Проверяем, существует ли такая запись
            cursor.execute("""
                DELETE FROM voice 
                WHERE id_client = %s AND id_election = %s;
            """, (client_id, election_id))
            if cursor.rowcount > 0:
                print(f"Клиент с ID {client_id} удален из голосования.")
            else:
                print(f"Запись для клиента с ID {client_id} не найдена в этом голосовании.")

    # Фиксируем изменения
    conn.commit()


def work_election(admin_password):
    conn = connect_to_cik_db(admin_password)
    cursor = conn.cursor()
    while True:
        try:
            clear_console()
            # 1. Вывод всех не завершенных голосований
            cursor.execute("""
                SELECT id, title, date_create 
                FROM elections 
                WHERE date_completion IS NULL OR date_active IS NULL;
            """)
            elections = cursor.fetchall()

            if not elections:
                print("\nНет не завершенных или не запущенных голосований.")
                wait_for_user()
                conn.rollback()
                cursor.close()
                conn.close()
                return

            print("\nСписок не завершенных и не запущенных голосований:")
            for election in elections:
                print(f"ID: {election[0]}, Title: {election[1]}, Date Created: {election[2]}")

            election_id = input("\nВведите ID для работы с голосованием или 'exit' для выхода: ").strip()

            if election_id.lower() == 'exit':
                return
            while True:
                clear_console()
                # 2. Получаем подробную информацию о выбранном голосовании
                election_id = int(election_id)
                cursor.execute("""
                    SELECT title, option_count 
                    FROM elections 
                    WHERE id = %s;
                """, (election_id,))
                election = cursor.fetchone()

                if election is None:
                    print("\nГолосование с таким ID не найдено.")
                    wait_for_user()
                    break

                title, option_count, date_active = election
                print(f"\nИнформация о голосовании:")
                print(f"ID: {election_id}, Title: {title}, Option Count: {option_count}")

                cursor.execute("""
                    SELECT option_number, option_text 
                    FROM election_options 
                    WHERE id_election = %s;
                """, (election_id,))
                options = cursor.fetchall()

                print("\nВарианты ответов:")
                for option in options:
                    print(f"Option {option[0]}: {option[1]}")

                # 3. Меню действий
                action = input("\nЧто хотите сделать? (1-Изменить название, 2-Изменить варианты ответов, "
                                "3-Добавить избирателя, 4-Удалить избирателя, 5-Удалить голосование"
                                "6-Запустить сбор ключей, 7-Сменить голосование, 8-Назад в меню): ").strip()

                if action == '1':
                    # Изменить название голосования
                    new_title = input("Введите новое название голосования: ").strip()
                    cursor.execute("""
                        UPDATE elections 
                        SET title = %s 
                        WHERE id = %s;
                    """, (new_title, election_id))
                    print("\nНазвание голосования успешно изменено.")
                    wait_for_user()
                    conn.commit()
                    continue

                elif action == '2':
                    # Изменить варианты ответов
                    print("\nРедактирование вариантов ответа:")
                    sub_action = input("Что хотите сделать? (1-Удалить вариант, 2-Добавить вариант, 3-Назад): ").strip()

                    if sub_action == '1':
                        # Удалить вариант
                        option_number = int(input("Введите номер варианта для удаления: ").strip())
                        cursor.execute("""
                            DELETE FROM election_options 
                            WHERE id_election = %s AND option_number = %s;
                        """, (election_id, option_number))
                        cursor.execute("""
                            UPDATE elections
                            SET option_count = option_count - 1
                            WHERE id = %s;
                        """, (election_id,))
                        print(f"\nВариант {option_number} успешно удален.")
                        wait_for_user()
                        conn.commit()
                        # Сдвиг номеров вариантов
                        cursor.execute("""
                            UPDATE election_options
                            SET option_number = option_number - 1
                            WHERE id_election = %s AND option_number > %s;
                        """, (election_id, option_number))
                        conn.commit()
                        continue

                    elif sub_action == '2':
                        # Добавить вариант
                        option_text = input("Введите текст нового варианта ответа: ").strip()
                        cursor.execute("""
                            INSERT INTO election_options (id_election, option_number, option_text, result)
                            VALUES (%s, %s, %s, %s);
                        """, (election_id, option_count + 1, option_text, None))
                        cursor.execute("""
                            UPDATE elections
                            SET option_count = option_count + 1
                            WHERE id = %s;
                        """, (election_id,))
                        print(f"\nВариант '{option_text}' успешно добавлен.")
                        wait_for_user()
                        conn.commit()
                        continue

                    elif sub_action == '3':
                        continue

                elif action == '3':
                    # Добавить избирателя
                    add_client(admin_password, election_id)
                    continue

                elif action == '4':
                    # Удалить избирателя
                    delete_client(admin_password, election_id)
                    continue

                elif action == '5':
                    # Удалить голосование
                    delete_election(admin_password, election_id)
                    continue

                elif action == '6':
                    # Запустить сбор ключей
                    start_key(admin_password, election_id)
                    break

                elif action == '7':
                    # Сменить голосование
                    break

                elif action == '8':
                    # Назад в меню
                    conn.rollback()
                    cursor.close()
                    conn.close()
                    return

                else:
                print("\nНекорректный ввод. Попробуйте снова.")
                wait_for_user()
                continue


            except Exception as e:
                print(f"Ошибка при работе с голосованием: {e}")
                wait_for_user()
                conn.rollback()
                cursor.close()
                conn.close()


# Основная функция для запроса ключей от ЦСК
def start_key(admin_password, election_id):
    try:
        # 1. Получаем данные о голосовании (title и public_key)
        cursor.execute("""
            SELECT title, public_key
            FROM elections
            WHERE id = %s;
        """, (election_id,))
        election_data = cursor.fetchone()

        if not election_data:
            print(f"Голосование с id {election_id} не найдено.")
            wait_for_user()
            return

        title, public_key = election_data
        print(f"Запрашиваем ключи для голосования. Название: {title}")

        # 2. Получаем участников голосования (id_client из таблицы voice)
        cursor.execute("""
            SELECT id_client
            FROM voice
            WHERE id_election = %s;
        """, (election_id,))
        participants = cursor.fetchall()

        # 3. Получаем имена участников
        names = []
        ids = []
        for participant in participants:
            id_client = participant[0]
            cursor.execute("""
                SELECT name
                FROM client
                WHERE id = %s;
            """, (id_client,))
            client_data = cursor.fetchone()

            if client_data:
                name = client_data[0]
                names.append(name)
                ids.append(id_client)

        count_name = len(names)

        if count_name == 0:
            print("Нет участников для голосования.")
            wait_for_user()
            return

        print(f"Всего участников для голосования: {count_name}")

        # 4. Формируем файл для ЦСК
        csk_folder = Path('message_sent') / "CIK"
        if not csk_folder.exists():
            csk_folder.mkdir(parents=True)

        file_name = f"cik_reg_csk_{gen_salt()}.txt"
        file_path = csk_folder / file_name

        # Формируем структуру данных для отправки
        data_name_id = {
            "name": names,
            "id_client": ids
        }

        # Записываем файл с запросом на сбор ключей
        if created_csk_message(file_path, title, election_id, public_key, count_name, data_name_id):
            print(f"Запрос на ключи успешно отправлен. Файл: {file_path}")
            wait_for_user()
        else:
            print(f"Ошибка при создании запроса на ключи.")
            wait_for_user()

        # 5. Формируем data_number_text из таблицы election_options
        cursor.execute("""
            SELECT option_number, option_text
            FROM election_options
            WHERE id_election = %s;
        """, (election_id,))
        options = cursor.fetchall()

        data_number_text = [
            {"option_number": option[0], "option_text": option[1]} for option in options
        ]

        # 6. Перебираем всех участников в таблице voice и получаем их данные
        cursor.execute("""
            SELECT id_client
            FROM voice
            WHERE id_election = %s;
        """, (election_id,))
        participants = cursor.fetchall()

        # 7. Для каждого участника формируем файл с приглашением на голосование
        sent_message_folder = Path('sent_message')
        if not sent_message_folder.exists():
            sent_message_folder.mkdir(parents=True)

        for participant in participants:
            id_client = participant[0]

            # Получаем имя клиента
            cursor.execute("""
                SELECT name
                FROM client
                WHERE id = %s;
            """, (id_client,))
            client_data = cursor.fetchone()

            if client_data:
                client_name = client_data[0]
                # Формируем путь к файлу с приглашением
                file_name = f"{title}_invitation_to_vote_{gen_salt()}.txt"
                user_folder = sent_message_folder / client_name

                if not user_folder.exists():
                    user_folder.mkdir(parents=True)

                file_path = user_folder / file_name

                # Создаем файл с приглашением
                if created_reg_client_message(file_path, title, election_id, count_number, data_number_text):
                    print(f"Приглашение для {client_name} успешно отправлено.")
                    wait_for_user()
                else:
                    print(f"Не удалось отправить приглашение для {client_name}.")
                    wait_for_user()
            else:
                print(f"Не найдено имя клиента с id {id_client}.")
                wait_for_user()

    except Exception as e:
        print(f"Ошибка при запросе ключей: {e}")
        wait_for_user()


#завершить голосование
def end_election(election_id):
    try:
        clear_console()
        # Устанавливаем дату завершения голосования
        current_date = datetime.now()
        cursor.execute("""
            UPDATE elections 
            SET date_completion = %s 
            WHERE id = %s;
        """, (current_date, election_id))
        
        # Получаем количество вариантов ответа
        cursor.execute("""
            SELECT option_count, title 
            FROM elections 
            WHERE id = %s;
        """, (election_id,))
        election_data = cursor.fetchone()

        if not election_data:
            print("Голосование не найдено.")
            wait_for_user()
            return

        option_count, title = election_data

        # Считаем количество голосов за каждый вариант
        cursor.execute("""
            SELECT number_vote, COUNT(*) 
            FROM bilutens 
            WHERE id_election = %s 
            GROUP BY number_vote;
        """, (election_id,))
        vote_results = dict(cursor.fetchall())  # {номер_варианта: кол-во_голосов}

        # Обновляем результаты в election_options
        for option_num in range(1, option_count + 1):
            votes = vote_results.get(option_num, 0)
            cursor.execute("""
                UPDATE election_options 
                SET result = %s 
                WHERE id_election = %s AND option_number = %s;
            """, (votes, election_id, option_num))

        # Фиксируем изменения
        conn.commit()

        # Выводим итоги голосования
        print(f"\nГолосование завершено: ID = {election_id}, Title = {title}")
        print("Итоги голосования:")

        cursor.execute("""
            SELECT option_number, option_text, result 
            FROM election_options 
            WHERE id_election = %s 
            ORDER BY option_number;
        """, (election_id,))
        options = cursor.fetchall()

        for option in options:
            print(f"Вариант {option[0]}: {option[1]} — голосов: {option[2]}")
        mailing_result(election_id)
        wait_for_user()

    except Exception as e:
        print(f"Ошибка завершения голосования: {e}")
        wait_for_user()


# Основная функция для рассылки результатов голосования
def mailing_result(election_id):
    try:
        # 1. Получаем данные о голосовании (title и option_count)
        cursor.execute("""
            SELECT title, option_count
            FROM elections
            WHERE id = %s;
        """, (election_id,))
        election_data = cursor.fetchone()

        if not election_data:
            print(f"Голосование с id {election_id} не найдено.")
            return

        title, option_count = election_data
        print(f"Готовим результаты для голосования. Название: {title}, Количество вариантов: {option_count}")

        # 2. Получаем все варианты ответов (option_number, option_text, result) из таблицы election_options
        cursor.execute("""
            SELECT option_number, option_text, result
            FROM election_options
            WHERE id_election = %s;
        """, (election_id,))
        election_options = cursor.fetchall()

        data_nember_text_result = {
            "option_number": [option[0] for option in election_options],
            "option_text": [option[1] for option in election_options],
            "option_result": [option[2] for option in election_options]
        }

        # 3. Получаем все записи из таблицы bilutens для формирования данных
        cursor.execute("""
            SELECT m, b
            FROM bilutens
            WHERE id_election = %s;
        """, (election_id,))
        bilutens_data = cursor.fetchall()

        count_mb = len(bilutens_data)
        data_mb = {
            "m": [entry[0] for entry in bilutens_data],
            "b": [entry[1] for entry in bilutens_data]
        }

        # 4. Получаем список пользователей, которым нужно разослать результаты
        cursor.execute("""
            SELECT id_client
            FROM voice
            WHERE id_election = %s;
        """, (election_id,))
        participants = cursor.fetchall()

        # 5. Для каждого участника отправляем файл с результатами
        for participant in participants:
            id_client = participant[0]

            # Получаем имя клиента по id
            cursor.execute("""
                SELECT name
                FROM client
                WHERE id = %s;
            """, (id_client,))
            client_data = cursor.fetchone()

            if client_data:
                name = client_data[0]

                # Папка для отправленных сообщений
                sent_folder = Path('sent_message') / name
                if not sent_folder.exists():
                    sent_folder.mkdir(parents=True)

                # Формируем имя файла
                file_name = f"{title}_result_{gen_salt()}.txt"
                file_path = sent_folder / file_name

                # Записываем файл с результатами
                if created_res_client_messgae(file_path, title, election_id, option_count, data_nember_text_result, count_mb, data_mb):
                    print(f"Результаты для {name} успешно отправлены. Файл: {file_path}")
                else:
                    print(f"Ошибка при создании файла с результатами для {name}.")
                    wait_for_user()
            else:
                print(f"Имя для клиента с id {id_client} не найдено.")
                wait_for_user()

    except Exception as e:
        print(f"Ошибка при рассылке результатов: {e}")
        wait_for_user()


#активные голосования
def active_election(admin_password):
    conn = connect_to_cik_db(admin_password)
    cursor = conn.cursor()

    while True:
        clear_console()
        print("Активные голосования:\n")

        cursor.execute("""
            SELECT e.id, e.title
            FROM elections e
            JOIN election_options eo ON e.id = eo.id_election
            WHERE eo.result IS NULL AND e.date_active IS NOT NULL
            GROUP BY e.id, e.title;
        """)
        elections = cursor.fetchall()

        if not elections:
            print("Нет активных голосований.")
            wait_for_user()
            break

        # Выводим все активные голосования
        for row in elections:
            print(f"ID: {row[0]}, Заголовок: {row[1]}")

        # Вводим ID для работы с голосованием
        choice = input("\nВведите ID голосования для получения подробной информации или нажмите Enter для выхода: ").strip()

        if not choice:
            break  # Выход из функции

        try:
            id_election = int(choice)
            cursor.execute("""
                SELECT title, date_create, date_active
                FROM elections
                WHERE id = %s;
            """, (id_election,))
            election_info = cursor.fetchone()

            if election_info:
                title, date_create, date_active = election_info
                print(f"\nГолосование: {title}")
                print(f"Дата создания: {date_create}")
                print(f"Дата активации: {date_active}")

                # Получаем все варианты выбора с результатами
                cursor.execute("""
                    SELECT option_number, option_text
                    FROM election_options
                    WHERE id_election = %s AND result IS NOT NULL
                    ORDER BY option_number;
                """, (id_election,))
                options = cursor.fetchall()

                if options:
                    print("\nВарианты выбора:")
                    for option in options:
                        option_number, option_text, result = option
                        print(f"№ {option_number} - {option_text}")
                        wait_for_user()
                else:
                    print("Нет вриантов для этого голосования.")
                    wait_for_user()
                choice=input("Завершить голосование?(1-да/2-нет)")
                if '1' == choice
                    end_election(id_election)


            else:
                print("Голосование с таким ID не найдено.")
                wait_for_user()

        except ValueError:
            print("Введите корректный числовой ID.")
            wait_for_user()
        
        # Спрашиваем, хотим ли мы посмотреть информацию о других завершенных голосованиях
        again = input("\nХотите посмотреть другие завершенные голосования? (1-да/2-нет): ").strip().lower()
        if again != '1':
            break  # Выход из функции

    conn.commit()
    cursor.close()
    conn.close()


#завершенные голосования
def endent_election(admin_password):
    conn = connect_to_cik_db(admin_password)
    cursor = conn.cursor()

    while True:
        clear_console()
        print("Завершенные голосования:\n")

        # Получаем список голосований с результатами в таблице election_options
        cursor.execute("""
            SELECT e.id, e.title 
            FROM elections e
            JOIN election_options eo ON e.id = eo.id_election
            WHERE eo.result IS NOT NULL
            GROUP BY e.id, e.title;
        """)
        elections = cursor.fetchall()

        if not elections:
            print("Нет завершенных голосований.")
            input("Нажмите Enter для продолжения...")
            break

        # Выводим все завершенные голосования
        for row in elections:
            print(f"ID: {row[0]}, Заголовок: {row[1]}")

        # Вводим ID для работы с голосованием
        choice = input("\nВведите ID голосования для получения подробной информации или нажмите Enter для выхода: ").strip()

        if not choice:
            break  # Выход из функции

        try:
            id_election = int(choice)
            cursor.execute("""
                SELECT title, date_create, date_active, date_completion
                FROM elections
                WHERE id = %s;
            """, (id_election,))
            election_info = cursor.fetchone()

            if election_info:
                title, date_create, date_active, date_completion = election_info
                print(f"\nГолосование: {title}")
                print(f"Дата создания: {date_create}")
                print(f"Дата активации: {date_active}")
                print(f"Дата завершения: {date_completion}")

                # Получаем все варианты выбора с результатами
                cursor.execute("""
                    SELECT option_number, option_text, result
                    FROM election_options
                    WHERE id_election = %s AND result IS NOT NULL
                    ORDER BY option_number;
                """, (id_election,))
                options = cursor.fetchall()

                if options:
                    print("\nВарианты выбора:")
                    for option in options:
                        option_number, option_text, result = option
                        print(f"№ {option_number} - {option_text} - {result} голосов")
                else:
                    print("Нет результатов для этого голосования.")

            else:
                print("Голосование с таким ID не найдено.")

        except ValueError:
            print("Введите корректный числовой ID.")
        
        # Спрашиваем, хотим ли мы посмотреть информацию о других завершенных голосованиях
        again = input("\nХотите посмотреть другие завершенные голосования? (y/n): ").strip().lower()
        if again != 'y':
            break  # Выход из функции

    conn.commit()
    cursor.close()
    conn.close()


def menu_client(admin_password):
    conn = connect_to_cik_db(admin_password)
    cursor = conn.cursor()

    while True:
        clear_console()
        print("Пользователи в системе:")
        cursor.execute("SELECT id, name FROM client;")
        clients = cursor.fetchall()
        for row in clients:
            print(f"{row[0]}: {row[1]}")
        print("\n1 - Добавить пользователя\n2 - Удалить пользователя\n3 - Назад в меню")
        sub_choice = input("Ваш выбор: ").strip()
        if sub_choice=='1':
            while True:
                name = input("Введите имя нового пользователя (или Enter для отмены): ").strip()
                if not name:
                    break
                cursor.execute("SELECT id FROM client WHERE name = %s;", (name,))
                if cursor.fetchone():
                    print("Пользователь с таким именем уже существует.")
                    again = input("Введите 1 чтобы попробовать другое имя, Enter чтобы выйти: ").strip()
                    if again != "1":
                        break
                now = datetime.now()
                cursor.execute("INSERT INTO client (name, date) VALUES (%s, %s) RETURNING id;", (name, now))
                new_id = cursor.fetchone()[0]
                conn.commit()

                folder_path = os.path.join("sent_message", name)
                file_name = f"{name}_start_client_{gen_salt()}.txt"
                file_path = os.path.join(folder_path, file_name)
                if created_start_client_message(file_path, name, new_id):
                    print("Пользователь добавлен и файл создан.")
                else:
                    print("Ошибка при создании стартового файла.")
                wait_for_user()
                break

        elif sub_choice=='2':
            choice = input("\nВведите id пользователя для работы или нажмите Enter для выхода: ").strip()
            if not choice:
                break
            try:
                id_client = int(choice)
                cursor.execute("SELECT id, name, date FROM client WHERE id = %s;", (id_client,))
                user = cursor.fetchone()
                if not user:
                    print("Пользователь с таким ID не найден.")
                    wait_for_user()
                    continue
                confirm = input("Вы уверены, что хотите удалить пользователя? (1-да/2-нет): ").lower()
                if confirm == '1':
                    cursor.execute("DELETE FROM client WHERE id = %s;", (id_client,))
                    conn.commit()
                    print("Пользователь удален.")
                    wait_for_user()
                    continue
            except ValueError:
                print("Введите корректный числовой ID.")
                wait_for_user()
                continue

        elif sub_choice=='3':
            conn.commit()
            cursor.close()
            conn.close()
            return  # выход в главное меню

        else:
            print("Некорректный выбор.")
            wait_for_user()


def main():
    data = handle_password()
    if data == None:
        return
    while True:
        clear_console()
        print("Главное меню:")
        print("1. Чтение сообщения")
        print("2. Пользователи")
        print("3. Голосования")
        print("4. Выход")
        choice = input("Выберите действие: ")

        if choice == '1':
            read_message(data[0])
        elif choice == '2':
            menu_client(data[0])
        elif choice == '3':
            menu_bd(data[0])                
        elif choice == '4':
            print("Выход из программы.")
            return
        else:
            print("Некорректный выбор. Попробуйте снова.")


# Основная функция
if __name__ == "__main__":
    main()