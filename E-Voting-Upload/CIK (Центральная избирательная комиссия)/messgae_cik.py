#Ответ от ЦСК
def read_csk_message(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["id_election"], data["date"], data["count_key"], data["data_key"]


#Скрытая метка
def read_blind_client_messgae(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["id_client"], data["date"], data["m_blind"], data["ds_client_blind"]


#Голос
def read_vot_cik_messgae(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["id_election"], data["date"], data["encrypted_data"]


#Добавление/обновление ключа и голосования для ЦСК
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
