import os
import json
import fnmatch
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode, b64decode
import hashlib
from datetime import datetime
import psycopg2
from psycopg2 import sql
import random
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes


def wait_for_user():
    input("\nНажмите любую клавишу, чтобы продолжить...")


# --- Генерация RSA ключей ---
def generate_rsa_key_pair(bits=2048):
    key = RSA.generate(bits)
    return key.publickey().export_key(format='DER'), key.export_key(format='DER')  # BYTEA


def bytes_to_psql_bytea(data: bytes):
    """Готовит данные для вставки в поле BYTEA PostgreSQL."""
    return psycopg2.Binary(data)


def psql_bytea_to_bytes(bytea_field) -> bytes:
    """При извлечении BYTEA из базы он уже bytes, но эта функция — для ясности."""
    return bytes(bytea_field)


# --- Создание метки M ---
def generate_m():
    return get_random_bytes(32)  # 256-битная случайная строка


# --- Слепление M в Mbl: Mbl = M * r^e mod n ---
def blind_message(M: bytes, r: int, pub_key_der: bytes) -> bytes:
    pub_key = import_rsa_key(pub_key_der)
    M_int = bytes_to_long(M)
    Mbl = (M_int * pow(r, pub_key.e, pub_key.n)) % pub_key.n
    return long_to_bytes(Mbl)


# --- Подпись слепой метки Mbl ---
def sign_message_blinded(priv_key_der: bytes, message_bytes: bytes) -> bytes:
    key = import_rsa_key(priv_key_der)
    h = SHA256.new(message_bytes)
    return pkcs1_15.new(key).sign(h)


  #"""Генерирует случайную строку с 5-значным числом."""


# --- Снятие слепоты подписи ---
def unblind_signature(blinded_signature: bytes, r: int, pub_key_der: bytes) -> bytes:
    key = import_rsa_key(pub_key_der)
    r_inv = inverse(r, key.n)
    sig_int = bytes_to_long(blinded_signature)
    return long_to_bytes((sig_int * r_inv) % key.n)


# --- Шифрование бюллетеня ---
def encrypt_ballot(pub_key_der: bytes, M: bytes, DS: bytes, B: int) -> bytes:
    key = import_rsa_key(pub_key_der)
    cipher = PKCS1_OAEP.new(key)
    ballot = json.dumps({
        "M": M.hex(),
        "DS": DS.hex(),
        "B": B
    }).encode()
    return cipher.encrypt(ballot)


def gen_salt():
  return str(random.randint(10000, 99999))


#Ключ для голосования для ЦСК
def create_csk_message(file_path, name, id_client, id_election, key):
    data = {
        "name": name,
        "id_client": id_client,
        "date": str(datetime.now()),
        "id_election": id_election,
        "key": str(key)
    }
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f)
        return True
    except:
        return False


#Скрытая метка
def create_blind_cik_messgae(file_path, id_client, id_election, m_blind, ds_client_blind):
    data = {
        "id_client": id_client,
        "id_election": id_election,
        "date": str(datetime.now()),
        "m_blind": str(m_blind),
        "ds_client_blind": str(ds_client_blind)
    }
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f)
        return True
    except:
        return False


#Голос
def create_vot_cik_messgae(file_path, id_election, encrypted_data):
    data = {
        "id_election": id_election,
        "date": str(datetime.now()),
        "encrypted_data": str(encrypted_data)
    }
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f)
        return True
    except:
        return False


#Слепая подпись для голосования
def read_ds_cik_messgae(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["id_client"], data["date"], data["id_election"], encode(data["ds_cik_blind"])


#Приглашение на голосование
def read_reg_cik_message(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["title"], data["id_election"], data["date"], data["count_number"], data["data_number_text"]


#Ключ для голосования от ЦСК
def read_csk_message(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["name"], data["id_client"], data["date"], data["id_election"], encode(data["key"])


#Результат голосования
def read_res_cik_messge(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return (
        data["title"], data["id_election"], data["date"],
        data["option_count"], data["data_nember_text_result"],
        data["count_mb"], data["data_mb"]
    )


#Регистрация пользователя
def read_start_client_message(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["name"], data["id_client"], data["date"]


#Подключение к базе данных
def connect_to_db(admin_password, name):
    """Подключение к базе данных."""
    return psycopg2.connect(
        dbname=name+"_BD",
        user="postgres",
        password=admin_password,
        host="localhost",
        port="5432"
    )


#Функция создания клиентской БД и таблиц
def create_client_database_and_tables(admin_password,name):
    # 1. Подключение к серверу PostgreSQL
    conn = connect_to_client_db(admin_password,name)
    conn.autocommit = True
    cursor = conn.cursor()

    # 2. Создание базы данных
    db_name = name+"_BD"
    try:
        cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
        print(f"База данных '{db_name}' успешно создана.")
    except psycopg2.errors.DuplicateDatabase:
        print(f"База данных '{db_name}' уже существует.")

    cursor.close()
    conn.close()

    # 3. Подключаемся к новой БД
    conn = connect_to_db(admin_password,name)
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


# Функция очистки консоли
def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')


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
    clear_console()
    # Проверка, существует ли файл с данными
    if os.path.exists("kesh_client.txt"):
        for _ in range(3):
            clear_console()
            password = input("Введите пароль: ")
            try:
                # Попытка дешифровать данные
                with open("kesh_client.txt", "r") as f:
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
        print("Приложение не активировано. Для активации убедитесь, что у вас есть регистрационный файл в диретории приложения")
        wait_for_user()
        filename = None  # по умолчанию, если не найден
        for file in os.listdir('.'):
            if fnmatch.fnmatch(file, '*_start_client_*.txt'):
                filename = file
                break  # если нужен только первый найденный файл
        if not filename:
            clear_console()
            print("Регистрационный файл не найден")
            wait_for_user()
            return None
        name, id_client, date = read_start_client_message(filename)
        while True:
            print("Файл регистрации найден для ",id_client ," " ,name ," выпуск файла:",date)
            choice = input("Активировать приложение этим файлом?(1-yes/2-no)")
            if choice == "1":
                clear_console()
                password = input("Придумайте пароль для входа в приложение: ")
                data = []
                while True:
                    chice=input("Введите пароль для работы с psql:")
                    if not check_db_password(chice):
                        print("Пароль не подходит для подключения к psql, введите корректный пароль")
                    else:
                        break
                data.append(chice)
                data.append(name)
                data.append(id_client)
                create_client_database_and_tables(data[0],data[1])
                # Шифрование и запись в файл
                encrypted_data = encrypt_data(password, data)
                with open("kesh_client.txt", "w") as f:
                    f.write(encrypted_data)
                nested_folder_path = os.path.join("sent_message","CSK")
                os.makedirs(nested_folder_path, exist_ok=True)
                nested_folder_path = os.path.join("sent_message","CIK")
                os.makedirs(nested_folder_path, exist_ok=True)
                nested_folder_path = os.path.join("read_message")
                os.makedirs(nested_folder_path, exist_ok=True)
                print("Приложение активировано")
                wait_for_user()
                return data
            elif choice == "2":
                print("Приложение осталось не активировано")
                wait_for_user()
                return None
            else:
                print("Некорректный ввод")
                wait_for_user()
   

# Основная функция для обработки файлов приглашений на голосование
def process_invitation_to_vote_files(files, mode, password, name, id_my):
    # Подключение к базе данных
    conn = connect_to_db(password, name)
    cursor = conn.cursor()

    for file in files:
        # Чтение данных из файла
        file_path = f"read_message/{file}"
        title, id_election, date, count_number, data_number_text = read_reg_cik_message(file_path)
        clear_console()
        # Выводим информацию о приглашении на голосование
        print(f"Приглашение на голосование по вопросу: {title}, создано: {date}")
        
        # Если mode = 2, спрашиваем, что делать
        if mode == 2:
            print("Что вы хотите сделать?")
            print("1 - Принять участие и отправить ключ ЦСК")
            print("2 - Не принимать участие")
            print("3 - Обработать позже")
            print("4 - Перейти к следующему типу сообщений")
            print("5 - Выйти в главное меню")
            action = input("Введите номер действия: ")

            if action == "1":
                # Принять участие и отправить ключ ЦСК
                public_key_my, private_key_my = generate_rsa_key_pair()
                public_key_my_bytea = bytes_to_psql_bytea(public_key_my)
                private_key_my_bytea = bytes_to_psql_bytea(private_key_my)

                # Вставляем запись в таблицу elections
                cursor.execute("""
                    INSERT INTO elections (id_election_cik, title, date, option_count, public_key_my, private_key_my,
                                           public_key_cik, metka, closing_multiplier_r, voting_b, ds_cik_blind)
                    VALUES (%s, %s, %s, %s, %s, %s, NULL, NULL, NULL, NULL, NULL)
                    RETURNING id
                """, (id_election, title, datetime.now(), count_number, public_key_my_bytea, private_key_my_bytea))
                election_id = cursor.fetchone()[0]

                # Вставляем данные в таблицу voting_options
                for i in range(count_number):
                    option_number = data_number_text["option_number"][i]
                    option_text = data_number_text["option_text"][i]
                    cursor.execute("""
                        INSERT INTO voting_options (election_id, option_number, option_text, result)
                        VALUES (%s, %s, %s, NULL)
                    """, (election_id, option_number, option_text))

                # Создаём файл с ключом ЦСК
                key_file_path = f"sent_message/CSK/{name}_reg_csk_{gen_salt()}.txt"
                create_csk_message(key_file_path, name, id_my, id_election, public_key_my)

                # Коммитим изменения
                conn.commit()
                print(f"Голосование {title} успешно зарегистрировано и ключ ЦСК отправлен.")
                wait_for_user()

            elif action == "2":
                # Не принимать участие
                print("Вы не приняли участие в голосовании.")
                os.remove(file_path)  # Удаляем файл
                print(f"Файл {file} удалён.")
                wait_for_user()
            
            elif action == "3":
                # Обработать позже
                print("Обработка отложена.")
                wait_for_user()
            
            elif action == "4":
                # Перейти к следующему типу сообщений
                print("Переходим к следующему типу сообщений.")
                wait_for_user()
                cursor.close()
                conn.close()
                return 1
            
            elif action == "5":
                # Выйти в главное меню
                print("Выход в главное меню.")
                cursor.close()
                conn.close()
                return 0
        
        elif mode == 1:
            # Автоматически выбрать 1: принять участие и отправить ключ ЦСК
            public_key_my, private_key_my = generate_rsa_key_pair()
            public_key_my_bytea = bytes_to_psql_bytea(public_key_my)
            private_key_my_bytea = bytes_to_psql_bytea(private_key_my)

            # Вставляем запись в таблицу elections
            cursor.execute("""
                INSERT INTO elections (id_election_cik, title, date, option_count, public_key_my, private_key_my,
                                       public_key_cik, metka, closing_multiplier_r, voting_b, ds_cik_blind)
                VALUES (%s, %s, %s, %s, %s, %s, NULL, NULL, NULL, NULL, NULL)
                RETURNING id
            """, (id_election, title, datetime.now(), count_number, public_key_my_bytea, private_key_my_bytea))
            election_id = cursor.fetchone()[0]

            # Вставляем данные в таблицу voting_options
            for i in range(count_number):
                option_number = data_number_text["option_number"][i]
                option_text = data_number_text["option_text"][i]
                cursor.execute("""
                    INSERT INTO voting_options (election_id, option_number, option_text, result)
                    VALUES (%s, %s, %s, NULL)
                """, (election_id, option_number, option_text))

            # Создаём файл с ключом ЦСК
            key_file_path = f"sent_message/CSK/{name}_reg_csk_{gen_salt()}.txt"
            create_csk_message(key_file_path, name, id_my, id_election, public_key_my)

            # Коммитим изменения
            conn.commit()
            print(f"Голосование {title} успешно зарегистрировано и ключ ЦСК отправлен.")

    # Закрытие соединения
    cursor.close()
    conn.close()
    return 1


# Основная функция для обработки файлов с ключами ЦСК
def process_key_csk_files(files, mode, password, name, id_my):
    # Подключение к базе данных
    conn = connect_to_db(password, name)
    cursor = conn.cursor()

    for file in files:
        clear_console()
        # Чтение данных из файла
        file_path = f"read_message/{file}"
        name_in_file, id_client, date, id_election, key = read_csk_message(file_path)

        # Проверка на совпадение name и id_client
        if name != name_in_file or id_my != id_client:
            print(f"Ошибка: файл {file} не для этого пользователя.")
            os.remove(file_path)  # Удаляем файл
            wait_for_user()
            continue

        # Если файл подходит
        print(f"Получен ключ для голосования. Информация о голосовании:")
        
        # Получаем информацию о голосовании
        cursor.execute("""
            SELECT title, date FROM elections WHERE id_election_cik = %s
        """, (id_election,))
        election_data = cursor.fetchone()
        
        if election_data:
            title, election_date = election_data
            print(f"Заголовок: {title}, Дата: {election_date}")
        else:
            print(f"Ошибка: голосование с id_election_cik = {id_election} не найдено.")
            wait_for_user()
            continue

        # Если mode == 2, запрашиваем, что делать
        if mode == 2:
            print("Что вы хотите сделать?")
            print("1 - Отправить цик скрытую метку")
            print("2 - Остановить участие")
            print("3 - Обработать позже")
            print("4 - Перейти к следующему типу сообщений")
            print("5 - Выйти в главное меню")
            action = input("Введите номер действия: ")

            if action == "1":
                # Генерируем метку и случайное число
                M = generate_m()
                r = bytes_to_long(get_random_bytes(32))

                # Получаем публичный ключ ЦИК
                cursor.execute("""
                    SELECT public_key_cik, private_key_my FROM elections WHERE id_election_cik = %s
                """, (id_election,))
                pub_cik, priv_cli = cursor.fetchone()
                pub_cik=psql_bytea_to_bytes(pub_cik)
                priv_cli=psql_bytea_to_bytes(priv_cli)

                # Слепляем сообщение
                Mbl = blind_message(M, r, pub_cik)

                # Подписываем слепленное сообщение
                DSi_bl = sign_message_blinded(priv_cli, Mbl)

                # Дополняем запись в таблице elections
                cursor.execute("""
                    UPDATE elections
                    SET metka = %s, closing_multiplier_r = %s
                    WHERE id_election_cik = %s
                """, (bytes_to_psql_bytea(M), bytes_to_psql_bytea(r), id_election))

                # Генерируем файл с меткой и подписью
                key_file_path = f"sent_message/CIK/{name}_hidden_label_{gen_salt()}.txt"
                create_blind_cik_message(key_file_path, id_my, id_election, Mbl, DSi_bl)

                # Коммитим изменения
                conn.commit()
                print(f"Метка успешно отправлена. Файл с меткой создан.")
                wait_for_user()
            
            elif action == "2":
                # Остановить участие
                cursor.execute("""
                    DELETE FROM elections WHERE id_election_cik = %s
                """, (id_election,))
                cursor.execute("""
                    DELETE FROM voting_options WHERE election_id = %s
                """, (id_election,))
                
                # Удаляем файл
                os.remove(file_path)
                print(f"Файл {file} удалён. Участие остановлено.")
                wait_for_user()
            
            elif action == "3":
                k=0
            
            elif action == "4":
                # Перейти к следующему типу сообщений
                cursor.close()
                conn.close()
                return 1
            
            elif action == "5":
                # Выйти в главное меню
                cursor.close()
                conn.close()
                return 0
        
        elif mode == 1:
            # Автоматически выбираем отправить скрытую метку
            M = generate_m()
            r = bytes_to_long(get_random_bytes(32))

            # Получаем публичный ключ ЦИК
            cursor.execute("""
                SELECT public_key_cik, private_key_my FROM elections WHERE id_election_cik = %s
            """, (id_election,))
            pub_cik, priv_cli = cursor.fetchone()
            pub_cik=psql_bytea_to_bytes(pub_cik)
            priv_cli=psql_bytea_to_bytes(priv_cli)

            # Слепляем сообщение
            Mbl = blind_message(M, r, pub_cik)

            # Подписываем слепленное сообщение
            DSi_bl = sign_message_blinded(priv_cli, Mbl)

            # Дополняем запись в таблице elections
            cursor.execute("""
                UPDATE elections
                SET metka = %s, closing_multiplier_r = %s
                WHERE id_election_cik = %s
            """, (bytes_to_psql_bytea(M), bytes_to_psql_bytea(r), id_election))

            # Генерируем файл с меткой и подписью
            key_file_path = f"sent_message/CIK/{name}_hidden_label_{gen_salt()}.txt"
            create_blind_cik_message(key_file_path, id_my, id_election, Mbl, DSi_bl)

            # Коммитим изменения
            conn.commit()
            print(f"Метка успешно отправлена. Файл с меткой создан.")

    # Закрытие соединения
    cursor.close()
    conn.close()
    return 1


# Основная функция для обработки файлов с анонимными подписями
def process_blind_signature_files(files, mode, password, name, id_my):
    # Подключение к базе данных
    conn = connect_to_db(password, name)
    cursor = conn.cursor()

    for file in files:
        clear_console()
        # Чтение данных из файла
        file_path = f"read_message/{file}"
        id_client, date, id_election, ds_cik_blind = read_ds_cik_message(file_path)

        # Проверка на совпадение id_client
        if id_my != id_client:
            print(f"Ошибка: файл {file} не для этого пользователя.")
            os.remove(file_path)  # Удаляем файл
            wait_for_user()
            continue

        # Если файл подходит
        print(f"Получена слепая подпись для голосования. Информация о голосовании:")

        # Получаем информацию о голосовании
        cursor.execute("""
            SELECT title, date FROM elections WHERE id_election_cik = %s
        """, (id_election,))
        election_data = cursor.fetchone()

        if election_data:
            title, election_date = election_data
            print(f"Заголовок: {title}, Дата: {election_date}")
        else:
            print(f"Ошибка: голосование не найдено.")
            wait_for_user()
            continue

        # Получаем варианты голосования
        cursor.execute("""
            SELECT option_number, option_text FROM voting_options WHERE election_id = %s
        """, (id_election,))
        options = cursor.fetchall()

        if not options:
            print(f"Ошибка: для голосования с id_election = {id_election} нет вариантов.")
            wait_for_user()
            continue
        
        print("Варианты для голосования:")
        for i, (option_number, option_text) in enumerate(options):
            print(f"{i}. {option_text}")
        
        # Запрос действия
        if mode == 2:
            print("Что вы хотите сделать?")
            print("1 - Проголосовать и отправить голос цик")
            print("2 - Остановить участие")
            print("3 - Обработать позже")
            print("4 - Перейти к следующему типу сообщений")
            print("5 - Выйти в главное меню")
            action = input("Введите номер действия: ")

            if action == "1":
                # Просим выбрать номер варианта
                while True:
                    B = int(input(f"Выберите номер варианта от 1 до {len(options)}: "))
                    if B <= 0 or B > len(options):
                        print("Некорректный номер варианта.")
                        wait_for_user()
                    else:
                        break

                # Получаем публичный ключ ЦИК и метку
                cursor.execute("""
                    SELECT public_key_cik, closing_multiplier_r, metka FROM elections WHERE id_election_cik = %s
                """, (id_election,))
                pub_cik, r, M = cursor.fetchone()
                pub_cik=psql_bytea_to_bytes(pub_cik)
                M=psql_bytea_to_bytes(M)

                # Снятие слепоты подписи
                DS = unblind_signature(ds_cik_blind, r, pub_cik)

                # Шифруем бюллетень
                encrypted_data = encrypt_ballot(pub_cik, M, DS, B)

                # Создаем файл с голосом
                file_name = f"voting_{gen_salt()}.txt"
                key_file_path = f"sent_message/CIK/{file_name}"
                create_vot_cik_message(key_file_path, id_election, encrypted_data)

                # Дополняем запись в таблице elections
                cursor.execute("""
                    UPDATE elections
                    SET voting_b = %s, ds_cik_blind = %s
                    WHERE id_election_cik = %s
                """, (B, bytes_to_psql_bytea(ds_cik_blind), id_election))

                # Коммитим изменения
                conn.commit()
                print(f"Голос успешно отправлен. Файл с голосом создан.")
                wait_for_user()

            elif action == "2":
                # Остановить участие
                cursor.execute("""
                    DELETE FROM elections WHERE id_election_cik = %s
                """, (id_election,))
                cursor.execute("""
                    DELETE FROM voting_options WHERE election_id = %s
                """, (id_election,))

                # Удаляем файл
                os.remove(file_path)
                print(f"Файл {file} удалён. Участие остановлено.")
                wait_for_user()

            elif action == "3":
                continue

            elif action == "4":
                # Перейти к следующему типу сообщений
                cursor.close()
                conn.close()
                return 1

            elif action == "5":
                # Выйти в главное меню
                cursor.close()
                conn.close()
                return 0
        elif mode == 1:
            # Автоматически голосуем (выбираем первый вариант)
            B = 0

            # Получаем публичный ключ ЦИК и метку
            cursor.execute("""
                SELECT public_key_cik, closing_multiplier_r, metka FROM elections WHERE id_election_cik = %s
            """, (id_election,))
            pub_cik, r, M = cursor.fetchone()

            pub_cik=psql_bytea_to_bytes(pub_cik)
            M=psql_bytea_to_bytes(M)

            # Снятие слепоты подписи
            DS = unblind_signature(ds_cik_blind, r, pub_cik)

            # Шифруем бюллетень
            encrypted_data = encrypt_ballot(pub_cik, M, DS, B)

            # Создаем файл с голосом
            file_name = f"voting_{gen_salt()}.txt"
            key_file_path = f"sent_message/CIK/{file_name}"
            create_vot_cik_message(key_file_path, id_election, encrypted_data)

            # Дополняем запись в таблице elections
            cursor.execute("""
                UPDATE elections
                SET voting_b = %s, ds_cik_blind = %s
                WHERE id_election_cik = %s
            """, (B, bytes_to_psql_bytea(ds_cik_blind), id_election))

            # Коммитим изменения
            conn.commit()
            print(f"Голос успешно отправлен. Файл с голосом создан.")
            wait_for_user()

    # Закрытие соединения
    cursor.close()
    conn.close()
    return 1


# Функция для обработки файлов *_result_*.txt
def process_result_files(files, mode, password, name):
    
    for file in files:
        clear_console()
        # Чтение данных из файла
        file_path = f"read_message/{file}"
        title, id_election, date, option_count, data_nember_text_result, count_mb, data_mb = read_res_cik_messge(file_path)
        
        # Подключаемся к базе данных
        conn = connect_to_db(password,name)
        cursor = conn.cursor()

        # Проверка наличия записи в таблице elections по id_election_cik
        cursor.execute("SELECT id, voting_b, metka FROM elections WHERE id_election_cik = %s", (id_election,))
        election_row = cursor.fetchone()

        if election_row is None:
            # Если записи нет, создаём новое голосование
            print(f"Голосование с id_election_cik = {id_election} не найдено. Создаём новое.")

            # Заполняем таблицу elections
            cursor.execute("""
                INSERT INTO elections (id_election_cik, title, option_count, date, public_key_cik, public_key_my, private_key_my,
                                       metka, closing_multiplier_r, voting_b, ds_cik_blind)
                VALUES (%s, %s, %s, %s, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
                RETURNING id
            """, (id_election, title, option_count, datetime.now()))
            
            election_id = cursor.fetchone()[0]

            # Заполняем таблицу voting_options
            for i in range(option_count):
                option_number = data_nember_text_result["option_number"][i]
                option_text = data_nember_text_result["option_text"][i]
                result = data_nember_text_result["option_result"][i]
                cursor.execute("""
                    INSERT INTO voting_options (election_id, option_number, option_text, result)
                    VALUES (%s, %s, %s, %s)
                """, (election_id, option_number, option_text, result))

            # Коммитим изменения
            conn.commit()
            print(f"Новая запись голосования создана для id_election_cik = {id_election}.")
            wait_for_user()

        else:
            # Если запись существует, проверяем подлинность данных
            election_id = election_row[0]
            voting_b = election_row[1]
            metka = election_row[2]

            if not voting_b or not metka:
                # Если voting_b или metka не заполнены, пропускаем проверку подлинности
                print(f"Голосование с id_election_cik = {id_election} прошло без проверки подлинности.")
                cursor.execute("""
                    UPDATE voting_options SET result = %s WHERE election_id = %s
                """, (data_nember_text_result["option_result"], election_id))
                conn.commit()
                print(f"Результаты обновлены для голосования {id_election}.")
                wait_for_user()
            else:
                # Проверяем пары (m, b) на соответствие
                m_list = psql_bytea_to_bytes(data_mb["m"])
                b_list = data_mb["b"]
                is_valid_vote = False
                
                for m, b in zip(m_list, b_list):
                    if encode(m) == voting_b and encode(b) == metka:
                        is_valid_vote = True
                        break
                
                if is_valid_vote:
                    print(f"Голосование для id_election_cik = {id_election} прошло успешно.")
                    wait_for_user()
                    # Если пара найдена, обновляем результат
                    cursor.execute("""
                        UPDATE voting_options SET result = %s WHERE election_id = %s
                    """, (data_nember_text_result["option_result"], election_id))
                    conn.commit()
                else:
                    print(f"Голос для id_election_cik = {id_election} засчитан неправильно, результат не записан, обратитесь к администратору.")
                    wait_for_user()

        # Закрытие соединения
        cursor.close()
        conn.close()


def read_message(password, name, id_my):
    # Запрос режима обработки (автоматически или вручную)
    while True:
        clear_console()
        mode = input("Введите режим обработки файлов: 1 - Автоматически, 2 - Вручную: ").strip()

        if mode not in ['1', '2']:
            print("Некорректный ввод. Выберите 1 для автоматической обработки или 2 для ручной.")
            wait_for_user()
            continue

        # Папка, в которой находятся входящие сообщения
        folder_path = 'read_message'

        # Проверяем, существует ли папка
        if not os.path.exists(folder_path):
            print(f"Папка {folder_path} не найдена.")
            wait_for_user()
            return

        # Считываем все файлы в папке
        files = os.listdir(folder_path)

        # Сортируем файлы на 4 категории по имени
        invitation_to_vote_files = [file for file in files if 'invitation_to_vote' in file]
        key_csk_files = [file for file in files if f'{name}_key_csk' in file]
        blind_signature_files = [file for file in files if f'{name}_blind_signature' in file]
        result_files = [file for file in files if 'result' in file]

        # Выводим статистику по файлам
        print(f"Найдено {len(invitation_to_vote_files)} файлов типа *_invitation_to_vote_*.txt")
        print(f"Найдено {len(key_csk_files)} файлов типа {name}_key_csk_*.txt")
        print(f"Найдено {len(blind_signature_files)} файлов типа {name}_blind_signature_*.txt")
        print(f"Найдено {len(result_files)} файлов типа *_result_*.txt")

        # Обрабатываем файлы в порядке: invitation_to_vote, key_csk, blind_signature, result
        if invitation_to_vote_files:
            print("\nОбработка файлов типа *_invitation_to_vote_*.txt...")
            if 0==process_invitation_to_vote_files(invitation_to_vote_files, mode, password, name, id_my):
                return
        
        if key_csk_files:
            print("\nОбработка файлов типа [name]_key_csk_*.txt...")
            if 0==rocess_key_csk_files(key_csk_files, mode, password, name, id_my):
                return
        
        if blind_signature_files:
            print("\nОбработка файлов типа [name]_blind_signature_*.txt...")
            if 0==process_blind_signature_files(blind_signature_files, mode, password, id_my):
                return
        
        if result_files:
            print("\nОбработка файлов типа *_result_*.txt...")
            process_result_files(result_files, mode, password)

        print("Обработка завершена.")
        wait_for_user()


def menu_bd(admin_password, name):
    clear_console()  # Очищаем консоль

    conn = connect_to_db(admin_password, name)
    cursor = conn.cursor()
    try:
        while True:
            clear_console()
            # 1. Получаем все голосования из таблицы elections
            cursor.execute("""
                SELECT id, title, date, private_key_my, ds_cik_blind
                FROM elections
            """)
            elections = cursor.fetchall()

            if not elections:
                print("Нет доступных голосований.")
                wait_for_user()
                cursor.close()
                conn.close()
                return

            # 2. Выводим информацию о голосованиях
            print("Список голосований:")
            for election in elections:
                election_id, title, date, private_key_my, ds_cik_blind = election

                # Определяем статус
                # Проверяем таблицу voting_options на наличие результата
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM voting_options 
                    WHERE election_id = %s AND result IS NOT NULL
                    """, (election_id,))
                result_count = cursor.fetchone()[0]
                if result_count > 0:
                    status = "Голосование завершено"
                else:
                    if ds_cik_blind:
                        status = "Ожидание завершения голосования"
                    else:
                        if private_key_my:
                            status = "Ожидание слепой подписи"
                        else:
                            status = "Ожидание ключа от ЦСК"

                # Выводим информацию
                print(f"ID: {election_id}, Title: {title}, Статус: {status}, Дата: {date}")

            # 3. Ввод id для работы с конкретным голосованием или выход
            election_id = input("\nВведите ID голосования для работы с ним или 'exit' для выхода: ")
            if election_id.lower() == 'exit':
                cursor.close()
                conn.close()
                return  # Выход из функции

            try:
                election_id = int(election_id)
            except ValueError:
                print("Неверный ввод. Попробуйте снова.")
                wait_for_user()
                continue

            # 4. Выводим подробную информацию о выбранном голосовании
            cursor.execute("""
                SELECT title, private_key_my, ds_cik_blind, option_count 
                FROM elections
                WHERE id = %s
            """, (election_id,))
            election_data = cursor.fetchone()
            clear_console()
            if not election_data:
                print("Голосование не найдено.")
                wait_for_user()
                continue

            title, private_key_my, ds_cik_blind, option_count = election_data
            clear_console()
            # Определяем статус
            # Проверяем таблицу voting_options на наличие результата
            cursor.execute("""
                SELECT COUNT(*) 
                FROM voting_options 
                WHERE election_id = %s AND result IS NOT NULL
                """, (election_id,))
            result_count = cursor.fetchone()[0]
            if result_count > 0:
                status = "Голосование завершено"
            else:
                if ds_cik_blind:
                    status = "Ожидание завершения голосования"
                else:
                    if private_key_my:
                        status = "Ожидание слепой подписи"
                    else:
                        status = "Ожидание ключа от ЦСК"

            # 5. Получаем варианты ответов из таблицы voting_options
            cursor.execute("""
                SELECT option_number, option_text, result 
                FROM voting_options
                WHERE election_id = %s
            """, (election_id,))
            options = cursor.fetchall()

            print(f"\nГолосование: {title}")
            print(f"Статус: {status}")
            print(f"Количество вариантов: {option_count}\n")

            for option in options:
                option_number, option_text, result = option
                print(f"Вариант {option_number}: {option_text}")
                if result is not None:
                    print(f"  Результат: {result}")

            # 6. Меню действий
            print("\nМеню действий:")
            print("1. Удалить голосование")
            print("2. Сменить голосование")
            print("3. Назад в главное меню")

            action = input("\nВыберите действие (1, 2, 3): ")

            if action == '1':
                # Удаляем голосование
                cursor.execute("""
                    DELETE FROM voting_options WHERE election_id = %s
                """, (election_id,))
                cursor.execute("""
                    DELETE FROM elections WHERE id = %s
                """, (election_id,))
                print(f"Голосование с ID {election_id} удалено.")
                wait_for_user()
            elif action == '2':
                k=0
            elif action == '3':
                cursor.close()
                conn.close()
                return
            else:
                print("Неверный выбор. Попробуйте снова.")
                wait_for_user()

    except Exception as e:
        print(f"Ошибка: {e}")
        wait_for_user()
    finally:
        cursor.close()
        conn.close()


def main():
    data = handle_password()
    if data == None:
        return
    while True:
        clear_console()
        print("Главное меню:")
        print("1. Чтение сообщения")
        print("2. База данных голосований")
        print("3. Выход")
        choice = input("Выберите действие: ")

        if choice == '1':
            read_message(data[0],data[1],data[2])
        elif choice == '2':
            menu_bd(data[0],data[1])                
        elif choice == '3':
            print("Выход из программы.")
            return
        else:
            print("Некорректный выбор. Попробуйте снова.")


# Основная функция
if __name__ == "__main__":
    main()