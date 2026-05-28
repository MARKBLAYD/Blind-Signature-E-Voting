#Ответ для клиента
def create_client_message(file_path, name, id_client, id_election, key):
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


#Ответ для ЦИК
def create_cik_message(file_path, id_election, count_key, data_key):
    data = {
        "id_election": id_election,
        "date": str(datetime.now()),
        "count_key": count_key,
        "data_key": data_key
    }
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f)
        return True
    except:
        return False
 

#Добавление/обновление ключа и голосования от ЦИК
def read_cik_message(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["id_election"], data["title"], data["date"], data["key_csk"], data["count_name"], data["data_name_id"]


#Добавление/обновление ключа избирателя
def read_client_message(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data["name"], data["id_client"], data["date"], data["id_election"], data["key"]

    