import os
import json
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


def wait_for_user():
    input("\nНажмите любую клавишу, чтобы продолжить...")

  #"""Генерирует случайную строку с 5-значным числом."""


def gen_salt():
  return str(random.randint(10000, 99999))


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


#Создание базы данных цск
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
        id_client INT,
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


# Преобразуем байты в строку base64 перед сериализацией
def encode_bytes_to_base64(byte_list):
    return [base64.b64encode(b).decode('utf-8') for b in byte_list]


# Преобразуем строку base64 обратно в байты
def decode_base64_to_bytes(base64_list):
    return [base64.b64decode(b) for b in base64_list]


#Ответ для клиента
def create_client_message(file_path, name, id_client, id_election, key):
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


#Ответ для ЦИК
def create_cik_message(file_path, id_election, count_key, data_key):
    # Преобразуем байтовые строки в base64
    encoded_data_key = {
        "id_client": data_key["id_client"],
        "key": encode_bytes_to_base64(data_key["key"])
    }
    
    data = {
        "id_election": id_election,
        "date": str(datetime.now()),
        "count_key": count_key,
        "data_key": json.dumps(encoded_data_key)
    }
    
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f)
        return True
    except Exception as e:
        print(f"Error writing file: {e}")
        return False
 

#Добавление/обновление ключа и голосования от ЦИК
def read_cik_message(file_path):
     try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data["id_election"], data["title"], data["date"], encode(data["key_csk"]), data["count_name"], json.loads(data["data_name_id"])
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

#Добавление/обновление ключа избирателя
def read_client_message(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["name"], data["id_client"], data["date"], data["id_election"], encode(data["key"])

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
    # Проверка, существует ли файл с данными
    clear_console()
    if os.path.exists("kesh_csk.txt"):
        for _ in range(3):
            clear_console()
            password = input("Введите пароль для входа в приложение: ")
            try:
                # Попытка дешифровать данные
                with open("kesh_csk.txt", "r") as f:
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
            if not check_db_password(chice):
                print("Пароль не подходит для подключения к psql, введите корректный пароль")
            else:
                break
        data.append(chice)
        create_database_and_tables(data[0])
        # Шифрование и запись в файл
        encrypted_data = encrypt_data(password, data)
        with open("kesh_csk.txt", "w") as f:
            f.write(encrypted_data)
        nested_folder_path = os.path.join("sent_message","CIK")
        os.makedirs(nested_folder_path, exist_ok=True)
        nested_folder_path = os.path.join("read_message")
        os.makedirs(nested_folder_path, exist_ok=True)
        print("Приложение активировано")
        wait_for_user()
        return data


# Чтение и обработка сообщений в папке read_message
def read_message(admin_password):
    folder = "read_message"
    files = sorted([f for f in os.listdir(folder) if f.endswith(".txt") and "_reg_csk_" in f])

    # Сортировка: сначала cik_reg_csk_*, потом остальные
    cik_files = [f for f in files if f.startswith("cik_reg_csk_")]
    other_files = [f for f in files if not f.startswith("cik_reg_csk_")]
    files_to_process = cik_files + other_files

    if not files_to_process:
        clear_console()
        print("Нет файлов для обработки.")
        wait_for_user()
        return
    clear_console()
    mode = input("Обработка файлов: 1 - автоматически, 2 - вручную: ")

    conn = connect_to_db(admin_password)
    cursor = conn.cursor()

    for filename in files_to_process:
        filepath = os.path.join(folder, filename)

        if filename.startswith("cik_reg_csk_"):
            try:
                id_election, title, date, key_cik, count_name, data_name_id = read_cik_message(filepath)
            except Exception as e:
                clear_console()
                print(f"Ошибка чтения файла {filename}: {e}")
                wait_for_user()
                continue
            clear_console()
            print(f"\nФайл: {filename}\nID выборов: {id_election}\nДата: {date}\nНазвание: {title}")

            if mode == "1":
                action = "1"
            else:
                action = input("1 - добавить, 2 - отвергнуть, 3 - позже, 4 - выйти в меню: ")

            if action == "2":
                os.remove(filepath)
                print("Файл удалён.")
                wait_for_user()
                continue
            elif action == "3":
                continue
            elif action == "4":
                break
            elif action == "1":
                now = datetime.now()
                cursor.execute("""
                    INSERT INTO election (title, id_election_cik, sending, date)
                    VALUES (%s, %s, %s, %s)
                """, (title, id_election, False, now))

                cursor.execute("""
                    INSERT INTO key_public (id_client, name, key_pub, id_election, date)
                    VALUES (%s, %s, %s, %s, %s)
                """, (None, "CIK", key_cik, id_election, now))

                for name, id_client in zip(data_name_id["name"], data_name_id["id_client"]):
                    cursor.execute("""
                        INSERT INTO key_public (id_client, name, key_pub, id_election, date)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (id_client, name, None, id_election, None))
                conn.commit()
                print("Добавлено голосование и участники.")
                wait_for_user()
                os.remove(filepath)
        else:
            try:
                name, id_client, date, id_election, key = read_client_message(filepath)
            except Exception as e:
                clear_console()
                print(f"Ошибка чтения файла {filename}: {e}")
                wait_for_user()
                continue

            cursor.execute("""
                SELECT * FROM key_public WHERE id_client = %s AND name = %s AND id_election = %s
            """, (id_client, name, id_election))
            user = cursor.fetchone()

            if not user:
                clear_console()
                print(f"Файл {filename} повреждён или участник не найден.")
                wait_for_user()
                continue

            cursor.execute("SELECT title FROM election WHERE id_election_cik = %s", (id_election,))
            result = cursor.fetchone()
            title = result[0] if result else "(не найдено)"
            clear_console()
            print(f"\nФайл: {filename}\nID клиента: {id_client}\nИмя: {name}\nID выборов: {id_election}\nГолосование: {title}")

            if mode == "1":
                action = "1"
            else:
                action = input("1 - добавить, 2 - отвергнуть, 3 - позже, 4 - выйти в меню: ")

            if action == "2":
                os.remove(filepath)
                print("Файл удалён.")
                wait_for_user()
                continue
            elif action == "3":
                continue
            elif action == "4":
                break
            elif action == "1":
                now = datetime.now()
                cursor.execute("""
                    UPDATE key_public SET key_pub = %s, date = %s
                    WHERE id_client = %s AND name = %s AND id_election = %s
                """, (id_client, name, key, id_election, now))
                conn.commit()
                print("Ключ клиента обновлён.")
                wait_for_user()
                os.remove(filepath)

    cursor.close()
    conn.close()
    clear_console()
    print("\nОбработка файлов завершена.")
    wait_for_user()


def menu_key(admin_password):
    conn = connect_to_db(admin_password)
    cursor = conn.cursor()

    while True:
        clear_console()
        print("\nДоступные голосования:")
        cursor.execute("SELECT id, title, id_election_cik, sending  FROM election;")
        elections = cursor.fetchall()

        if not elections:
            print("Нет голосований.")
            wait_for_user()
            break

        for row in elections:
            _, title, id_election_cik, sending = row
            status = "запущено" if sending else "завершено"
            print(f"{id_election_cik} | {status} | {title}")

        choice = input("\nВведите id для работы или 'exit' для выхода: ")
        if choice.lower() == 'exit':
            break
        # Преобразование строки в целое число
        try:
            choice = int(choice)  # Преобразуем строку в целое число
        except ValueError:
            print("Ошибка: введено не числовое значение.")
            wait_for_user()
            continue

        cursor.execute("SELECT * FROM election WHERE id_election_cik = %s;", (choice))
        election = cursor.fetchone()
        if not election:
            print("Голосование не найдено.")
            wait_for_user()
            continue
        clear_console()
        id_election_db, title, id_election_cik, sending, date = election
        status = "запущено" if sending else "завершено"
        print(f"\n{status} Голосование: {title}\nДата: {date}\n")

        while True:
            print("1 - Работа с участниками")
            print("2 - Запуск рассылки ключей")
            print("3 - Удалить голосование")
            print("4 - Сменить голосование")
            print("5 - Выйти в меню")

            sub_choice = input("Выбор: ")

            if sub_choice == '1':
                cursor.execute("""
                    SELECT id, name, key_pub FROM key_public
                    WHERE id_election = %s;
                """, (id_election_cik,))
                participants = cursor.fetchall()
                if not participants:
                    print("Нет участников.")
                    wait_for_user()
                    continue

                for pid, name, has_key in participants:
                    status = "есть ключ" if has_key else "нет ключа"
                    print(f"{pid}: {name} | {status}")

                user_id = input("Введите id участника или 'back' для возврата: ")
                if user_id.lower() == 'back':
                    continue
                try:
                    user_id = int(user_id)  # Преобразуем строку в целое число
                except ValueError:
                    print("Ошибка: введено не числовое значение.")
                    wait_for_user()
                    continue
                cursor.execute("SELECT id, name FROM key_public WHERE id = %s AND id_election = %s;", (user_id, id_election_cik))
                participant = cursor.fetchone()
                if not participant:
                    print("Участник не найден.")
                    wait_for_user()
                    continue

                print("1 - Обнулить ключ")
                print("2 - Удалить участника")
                print("3 - Назад")
                act = input("Выбор: ")
                if act == '1':
                    cursor.execute("UPDATE key_public SET key_pub = NULL, date = NULL WHERE id = %s;", (user_id,))
                    conn.commit()
                    print("Ключ обнулён.")
                    wait_for_user()
                elif act == '2':
                    cursor.execute("DELETE FROM key_public WHERE id = %s;", (user_id,))
                    conn.commit()
                    print("Участник удалён.")
                    wait_for_user()
                elif act == '3':
                    continue

            elif sub_choice == '2':
                cursor.execute("UPDATE election SET sending = TRUE WHERE id = %s;", (id_election_db,))
                conn.commit()

                # Получаем ключ CIK
                cursor.execute("""
                    SELECT key_pub FROM key_public
                    WHERE name = 'CIK' AND id_election = %s AND key_pub IS NOT NULL;
                """, (id_election_cik,))
                csk_key = cursor.fetchone()
                if not csk_key:
                    print("У CIK нет ключа для этого голосования.")
                    wait_for_user()
                    continue

                csk_key = csk_key[0]

                cursor.execute("""
                    SELECT id_client, name, key_pub FROM key_public
                    WHERE id_election = %s AND name != 'CSK' AND key_pub IS NOT NULL;
                """, (id_election_cik,))
                users = cursor.fetchall()

                for id_client, name, key in users:
                    name_plus=name+"_key_csk_"+gen_salt()+".txt"
                    user_folder = os.path.join("sent_message", name)
                    os.makedirs(user_folder, exist_ok=True)
                    file_path = os.path.join(user_folder, name_plus)
                    create_client_message(file_path, name, id_client, id_election_cik, csk_key)
                    print(f"Файл создан для пользователя {name}.")

                # Теперь файл для CSK
                cursor.execute("""
                    SELECT id_client, key_pub FROM key_public
                    WHERE id_election = %s AND key_pub IS NOT NULL AND name != 'CSK';
                """, (id_election_cik,))
                valid_users = cursor.fetchall()
                name_plus="cik_key_csk_"+gen_salt()+".txt"
                csk_folder = os.path.join("sent_message", "CSK")
                os.makedirs(csk_folder, exist_ok=True)
                file_path = os.path.join(csk_folder, name_plus)

                data_key = {
                    "id_client": [u[0] for u in valid_users],
                    "key": [u[1] for u in valid_users]
                }
                create_cik_message(file_path, id_election_cik, len(valid_users), data_key)
                print("Файл для CSK создан.")
                wait_for_user()

            elif sub_choice == '3':
                confirm = input("Вы уверены, что хотите удалить сбор ключей для голосования и всех участников? (1-да/2-нет): ")
                if confirm.lower() == '1':
                    cursor.execute("DELETE FROM key_public WHERE id_election = %s;", (id_election_cik,))
                    cursor.execute("DELETE FROM election WHERE id_election_cik = %s;", (id_election_cik,))
                    conn.commit()
                    print("Голосование и участники удалены.")
                    wait_for_user()
                    break

            elif sub_choice == '4':
                break

            elif sub_choice == '5':
                conn.commit()
                cursor.close()
                conn.close()
                return
            else:
                print("Неверный выбор.")
                wait_for_user()


def main():
    data = handle_password()
    if data==None:
        return
    while True:
        clear_console()
        print("Главное меню:")
        print("1. Чтение сообщения")
        print("2. База данных ключей")
        print("3. Выход")
        choice = input("Выберите действие: ")

        if choice == '1':
            read_message(data[0])
        elif choice == '2':
            menu_key(data[0])                
        elif choice == '3':
            print("Выход из программы.")
            return
        else:
            print("Некорректный выбор. Попробуйте снова.")

# Основная функция
if __name__ == "__main__":
    main()