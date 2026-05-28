import json
from datetime import datetime


#Регистрация пользователя
def read_start_client_message(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["name"], data["id_client"], data["date"]


#Ключ для голосования от ЦСК
def read_csk_message(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["name"], data["id_client"], data["date"], data["id_election"], data["key"]


#Приглашение на голосование
def read_reg_cik_message(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["title"], data["id_election"], data["date"], data["count_number"], data["data_number_text"]


#Слепая подпись для голосования
def read_ds_cik_messgae(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["id_client"], data["date"], data["id_election"], data["ds_cik_blind"]


#Результат голосования
def read_res_cik_messgae(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return (
        data["title"], data["id_election"], data["date"],
        data["option_count"], data["data_nember_text_result"],
        data["count_mb"], data["data_mb"]
    )


#Ключ для голосования для ЦСК
def create_csk_message(file_path, name, id_client, id_election, key):
    data = {
        "name": name,
        "id_client": id_client,
        "date": str(datetime.now()),
        "id_election": id_election,
        "key": key
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
        "m_blind": m_blind,
        "ds_client_blind": ds_client_blind
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
        "encrypted_data": encrypted_data
    }
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f)
        return True
    except:
        return False