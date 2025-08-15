from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from db import exist_db, init_db, add_connection, update_connection_disconnect, update_connection_traffic, get_all_connections
import subprocess
import os
import json


@asynccontextmanager
async def lifespan(app: FastAPI):
    # код при старте
    if not await exist_db():
        await init_db()
    yield
    # код при завершении (если нужно закрыть ресурсы)
app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Пути к логу, Easy-RSA и файлу пользователей
LOG_PATH = "/var/log/openvpn/server.log"
EASYRSA_PATH = "/etc/openvpn/easy-rsa/easyrsa"
INDEX_PATH = "/etc/openvpn/easy-rsa/keys/index.txt"
USERS_JSON_PATH = "/app/users.json"  # Файл для хранения email и описания
ZABBIX_SENDER = "/usr/bin/zabbix_sender"
ZABBIX_SERVER = os.environ.get("ZABBIX_SERVER", "your-zabbix-server-ip:10051")
ZABBIX_HOSTNAME = os.environ.get("ZABBIX_HOSTNAME", "vpn-server")

# Парсинг лога OpenVPN
def parse_openvpn_status():
    if not os.path.exists(LOG_PATH):
        print(f"Log file {LOG_PATH} does not exist")
        return {"clients": 0, "stats": []}
    
    try:
        with open(LOG_PATH, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading log file: {e}")
        return {"clients": 0, "stats": []}
    
    clients = []
    in_clients = False
    total_clients = 0
    print(f"Log lines: {lines[:10]}")  # Отладка
    
    for line in lines:
        line = line.strip()
        if line.startswith("HEADER,ROUTING_TABLE"):
            break
        if in_clients:
            if line.startswith("CLIENT_LIST"):
                try:
                    parts = line.split(',')
                    if len(parts) >= 9:
                        # Преобразуем байты в мегабайты
                        bytes_received = int(parts[5]) / (1024 * 1024)
                        bytes_sent = int(parts[6]) / (1024 * 1024)
                        clients.append({
                            "common_name": parts[1],
                            "real_address": parts[2],
                            "bytes_received": round(bytes_received, 2),  # Округляем до 2 знаков
                            "bytes_sent": round(bytes_sent, 2),
                            "connected_since": parts[7]
                        })
                        total_clients += 1
                    else:
                        print(f"Skipping invalid line: {line}")
                except Exception as e:
                    print(f"Error parsing line '{line}': {e}")
        if line.startswith("HEADER,CLIENT_LIST"):
            in_clients = True
    
    print(f"Parsed {total_clients} clients: {clients}")
    return {"clients": total_clients, "stats": clients}

# Чтение списка всех пользователей из index.txt
def get_all_users():
    users = []
    if not os.path.exists(INDEX_PATH):
        print(f"Index file {INDEX_PATH} does not exist")
        return users
    
    try:
        with open(INDEX_PATH, 'r') as f:
            for line in f:
                if line.startswith("V"):
                    parts = line.split('\t')
                    if len(parts) >= 5:
                        common_name = parts[-1].split('/CN=')[-1].strip()
                        if common_name.lower() != "server":
                            users.append({"common_name": common_name, "is_connected": False})
    except Exception as e:
        print(f"Error reading index file: {e}")
        return users
    
    # Проверяем подключённых клиентов
    status = parse_openvpn_status()
    connected_users = {client["common_name"] for client in status["stats"]}
    for user in users:
        user["is_connected"] = user["common_name"] in connected_users
    
    # Загружаем email и описание из JSON
    if os.path.exists(USERS_JSON_PATH):
        try:
            with open(USERS_JSON_PATH, 'r') as f:
                user_data = json.load(f)
            for user in users:
                for data in user_data:
                    if data["common_name"] == user["common_name"]:
                        user["email"] = data.get("email", "")
                        user["description"] = data.get("description", "")
                        break
                else:
                    user["email"] = ""
                    user["description"] = ""
        except Exception as e:
            print(f"Error reading users JSON: {e}")
    
    return sorted(users, key=lambda x: x["common_name"])  # Сортировка по имени

# Сохранение данных пользователя в JSON
def save_user_data(common_name, email="", description=""):
    user_data = []
    if os.path.exists(USERS_JSON_PATH):
        try:
            with open(USERS_JSON_PATH, 'r') as f:
                user_data = json.load(f)
        except:
            pass
    
    for user in user_data:
        if user["common_name"] == common_name:
            user["email"] = email
            user["description"] = description
            break
    else:
        user_data.append({
            "common_name": common_name,
            "email": email,
            "description": description
        })
    
    try:
        with open(USERS_JSON_PATH, 'w') as f:
            json.dump(user_data, f, indent=4)
    except Exception as e:
        print(f"Error saving users JSON: {e}")

# Удаление пользователя из JSON
def remove_user_data(common_name):
    if os.path.exists(USERS_JSON_PATH):
        try:
            with open(USERS_JSON_PATH, 'r') as f:
                user_data = json.load(f)
            user_data = [user for user in user_data if user["common_name"] != common_name]
            with open(USERS_JSON_PATH, 'w') as f:
                json.dump(user_data, f, indent=4)
        except Exception as e:
            print(f"Error removing user from JSON: {e}")

# Отправка метрик в Zabbix
def send_to_zabbix(metrics):
    try:
        for key, value in metrics.items():
            cmd = [
                ZABBIX_SENDER,
                "-z", ZABBIX_SERVER.split(":")[0],
                "-p", ZABBIX_SERVER.split(":")[1] if ":" in ZABBIX_SERVER else "10051",
                "-s", ZABBIX_HOSTNAME,
                "-k", key,
                "-o", str(value)
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Zabbix sender error: {e.stderr}")
    except Exception as e:
        print(f"Error sending to Zabbix: {e}")

# Добавление пользователя
@app.post("/add_user")
async def add_user(username: str = Form(...), email: str = Form(""), description: str = Form("")):
    try:
        cmd = ["/usr/local/bin/openvpn-addclient", username, email]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        save_user_data(username, email, description)
        return {"message": f"Пользователь {username} добавлен успешно"}
    except subprocess.CalledProcessError as e:
        return {"error": f"Command failed with exit code {e.returncode}: {e.stderr}"}
    except Exception as e:
        return {"error": str(e)}

# Удаление пользователя
@app.post("/revoke_user")
async def revoke_user(username: str = Form(...)):
    try:
        subprocess.run(["/usr/local/bin/openvpn-revoke", username],input="yes\n",text=True,check=True,capture_output=True)
        remove_user_data(username)
        return {"message": f"Пользователь {username} удален успешно"}
    except subprocess.CalledProcessError as e:
        return {"error": f"Command failed with exit code {e.returncode}: {e.stderr}"}
    except Exception as e:
        return {"error": str(e)}

# Дашбоард
@app.get("/")
async def dashboard(request: Request):
    status = parse_openvpn_status()
    all_users = get_all_users()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # обновляем БД
    for client in status["stats"]:
        # обновляем трафик активных
        await update_connection_traffic(client["common_name"], client["bytes_received"], client["bytes_sent"])

        # если подключения ещё нет в базе — добавляем
        connections = await get_all_connections()
        if not any(c["common_name"] == client["common_name"] and c["disconnected_at"] is None for c in connections):
            await add_connection(client["common_name"], client["connected_since"])

    # проверяем, кто отключился
    active_users = {c["common_name"] for c in status["stats"]}
    connections = await get_all_connections()
    for c in connections:
        if c["disconnected_at"] is None and c["common_name"] not in active_users:
            connected_at = datetime.strptime(c["connected_at"], "%Y-%m-%d %H:%M:%S")
            disconnected_at = now
            duration_minutes = int((datetime.now() - connected_at).total_seconds() // 60)
            await update_connection_disconnect(
                c["common_name"],
                disconnected_at,
                duration_minutes,
                c["bytes_received"],
                c["bytes_sent"]
            )

    connections = await get_all_connections()

    metrics = {"vpn.connected_clients": status["clients"]}
    send_to_zabbix(metrics)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "status": status,
        "all_users": all_users,
        "connections": connections
    })