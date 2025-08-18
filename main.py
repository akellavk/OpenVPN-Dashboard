from starlette import status as statushttp
from auth import create_access_token, get_current_active_user, User, get_current_user
from security import verify_password
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from db import init_db, add_connection, update_connection_disconnect, update_connection_traffic, get_all_connections, \
    add_user_db, remove_user_db, get_all_users_from_db, get_credentials_from_db
import subprocess
import os
import asyncio
import re
import logging

# Настройка логирования
LOG_PATH = "/app/log/server.log"
print("Log dir: {}".format(os.path.dirname(LOG_PATH)))
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
file_log = logging.FileHandler(LOG_PATH, encoding='utf-8')
console_out = logging.StreamHandler()
logging.basicConfig(handlers=(file_log, console_out), level=logging.INFO,
                    format='%(asctime)s - [%(levelname)s] [M: %(module)s] [Fun: %(funcName)s] - %(message)s',
                    datefmt='%d.%m.%Y %H:%M:%S')
logger = logging.getLogger(__name__)

#Token Scheme
sysadmin_scheme = OAuth2PasswordBearer(tokenUrl="Akellavk")

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
    asyncio.create_task(update_connections_periodically())
    yield

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

LOG_PATH = "/var/log/openvpn/server.log"
EVENT_LOG_PATH = "/var/log/openvpn.log"
INDEX_PATH = "/etc/openvpn/easy-rsa/keys/index.txt"
ZABBIX_SENDER = "/usr/bin/zabbix_sender"
ZABBIX_SERVER = os.environ.get("ZABBIX_SERVER", "your-zabbix-server-ip:10051")
ZABBIX_HOSTNAME = os.environ.get("ZABBIX_HOSTNAME", "vpn-server")

async def update_connections_periodically():
    while True:
        await update_connections()
        await asyncio.sleep(5)

async def update_connections():
    status = await parse_openvpn_status()
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"Updating connections at {now_str}, active clients: {len(status['stats'])}")

    for client in status["stats"]:
        await update_connection_traffic(
            client["common_name"],
            client["bytes_received"],
            client["bytes_sent"],
            client["updated"]
        )

        connections = await get_all_connections()
        if not any(c["common_name"] == client["common_name"] and c["disconnected_at"] is None for c in connections):
            await add_connection(
                client["common_name"],
                client["connected_since"],
                client["updated"]
            )
            logger.info(f"Added new connection for {client['common_name']} at {client['connected_since']}")

    active_users = {c["common_name"] for c in status["stats"]}
    connections = await get_all_connections()
    disconnect_times = await parse_disconnect_times()

    for c in connections:
        if c["disconnected_at"] is None and c["common_name"] not in active_users:
            disconnected_at = disconnect_times.get(c["common_name"], None)
            if disconnected_at:
                disconnected_at_dt = datetime.strptime(disconnected_at, "%Y-%m-%d %H:%M:%S")
                logger.info(f"Found disconnect time for {c['common_name']}: {disconnected_at}")
            else:
                # Корректировка на keepalive (30 секунд)
                disconnected_at_dt = now - timedelta(seconds=15)
                disconnected_at = disconnected_at_dt.strftime("%Y-%m-%d %H:%M:%S")
                logger.warning(f"No disconnect time found for {c['common_name']}, using {disconnected_at}")

            connected_at_dt = datetime.strptime(c["connected_at"], "%Y-%m-%d %H:%M:%S")
            duration_minutes = max(0, int((disconnected_at_dt - connected_at_dt).total_seconds() // 60))

            await update_connection_disconnect(
                c["common_name"],
                disconnected_at,
                duration_minutes,
                c["bytes_received"],
                c["bytes_sent"]
            )
            logger.info(f"Updated disconnect for {c['common_name']}: {disconnected_at}, duration: {duration_minutes} minutes")

async def parse_disconnect_times():
    disconnect_times = {}
    if not os.path.exists(EVENT_LOG_PATH):
        logger.error(f"Event log {EVENT_LOG_PATH} does not exist")
        return disconnect_times

    try:
        with open(EVENT_LOG_PATH, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f"Error reading event log: {e}")
        return disconnect_times

    # Парсим строки вида: "2025-08-15 18:12:59 us=133072 akellavk_m/192.168.1.1:4716 [akellavk_m] Inactivity timeout (--ping-restart), restarting"
    pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*? (\S+?)(?:/\d+\.\d+\.\d+\.\d+:\d+)? \[(\S+?)] Inactivity timeout")
    for line in lines:
        match = pattern.search(line)
        if match:
            timestamp = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
            common_name = match.group(2).split('/')[-1]  # Извлекаем common_name
            disconnect_times[common_name] = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            logger.debug(f"Parsed disconnect for {common_name}: {disconnect_times[common_name]}")

    return disconnect_times

async def parse_openvpn_status():
    if not os.path.exists(LOG_PATH):
        logger.error(f"Log file {LOG_PATH} does not exist")
        return {"clients": 0, "stats": []}

    try:
        with open(LOG_PATH, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f"Error reading log file: {e}")
        return {"clients": 0, "stats": []}

    clients = []
    in_clients = False
    total_clients = 0
    logger.debug(f"Log lines: {lines[:10]}")

    for line in lines:
        line = line.strip()
        if line.startswith("HEADER,ROUTING_TABLE"):
            break
        if in_clients:
            if line.startswith("CLIENT_LIST"):
                try:
                    parts = line.split(',')
                    if len(parts) >= 9:
                        bytes_received = int(parts[5]) / (1024 * 1024)
                        bytes_sent = int(parts[6]) / (1024 * 1024)
                        updated = datetime.fromtimestamp(int(parts[8])).strftime("%Y-%m-%d %H:%M:%S") if len(parts) > 8 and parts[8].isdigit() else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        clients.append({
                            "common_name": parts[1],
                            "real_address": parts[2],
                            "bytes_received": round(bytes_received, 2),
                            "bytes_sent": round(bytes_sent, 2),
                            "connected_since": parts[7],
                            "updated": updated
                        })
                        total_clients += 1
                    else:
                        logger.warning(f"Skipping invalid line: {line}")
                except Exception as e:
                    logger.error(f"Error parsing line '{line}': {e}")
        if line.startswith("HEADER,CLIENT_LIST"):
            in_clients = True

    logger.info(f"Parsed {total_clients} clients: {clients}")
    return {"clients": total_clients, "stats": clients}

async def get_all_users():
    users = []
    if not os.path.exists(INDEX_PATH):
        logger.error(f"Index file {INDEX_PATH} does not exist")
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
        logger.error(f"Error reading index file: {e}")
        return users

    status = await parse_openvpn_status()
    connected_users = {client["common_name"] for client in status["stats"]}
    for user in users:
        user["is_connected"] = user["common_name"] in connected_users

    try:
        user_data = await get_all_users_from_db()
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
        logger.error(f"Error reading users from DB: {e}")

    return sorted(users, key=lambda x: x["common_name"])

async def send_to_zabbix(metrics):
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
            logger.info(f"Sent to Zabbix: {key} = {value}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Zabbix sender error: {e.stderr}")
    except Exception as e:
        logger.error(f"Error sending to Zabbix: {e}")

@app.get("/")
async def dashboard(request: Request, current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login")

    status = await parse_openvpn_status()
    all_users = await get_all_users()
    connections = await get_all_connections()
    metrics = {"vpn.connected_clients": status["clients"]}
    await send_to_zabbix(metrics)
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "status": status,
        "all_users": all_users,
        "connections": connections
    })

@app.post("/add_user")
async def add_user(token: str = Depends(sysadmin_scheme), username: str = Form(...), email: str = Form(""), description: str = Form(""), current_user: User = Depends(get_current_active_user)):
    try:
        if not current_user:
            return RedirectResponse(url="/login", status_code=statushttp.HTTP_303_SEE_OTHER)
        if not token:
            raise HTTPException(status_code=400, detail="Token is required")
        if token != os.environ.get("AKELLAVK_TKN"):
            raise HTTPException(status_code=403, detail="Invalid bearer token")
        # Проверяем, существует ли файл .ovpn
        ovpn_file = f"/etc/openvpn/easy-rsa/keys/{username}.ovpn"
        if os.path.exists(ovpn_file):
            logger.error(f"User {username} already exists (OVPN file found)")
            raise HTTPException(status_code=400, detail=f"Пользователь {username} уже существует")
        else:
            logger.info(f"Пользователя не существует, добавляю {username}")

        # Выполняем команду openvpn-addclient
        cmd = ["/usr/local/bin/openvpn-addclient", username, email]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        await add_user_db(username, email, description)
        logger.info(f"User {username} added successfully")
        return {"message": f"Пользователь {username} добавлен успешно"}
    except subprocess.CalledProcessError as e:
        logger.error(f"Add user failed: {e.stderr}")
        return {"error": f"Command failed with exit code {e.returncode}: {e.stderr}"}
    except Exception as e:
        logger.error(f"Add user error: {e}")
        return {"error": str(e)}

@app.post("/revoke_user")
async def revoke_user(token: str = Depends(sysadmin_scheme),username: str = Form(...), current_user: User = Depends(get_current_active_user)):
    try:
        if not current_user:
            return RedirectResponse(url="/login", status_code=statushttp.HTTP_303_SEE_OTHER)
        if not token:
            raise HTTPException(status_code=400, detail="Token is required")
        if token != os.environ.get("AKELLAVK_TKN"):
            raise HTTPException(status_code=403, detail="Invalid bearer token")
        subprocess.run(["/usr/local/bin/openvpn-revoke", username], input="yes\n", text=True, check=True, capture_output=True)
        await remove_user_db(username)
        logger.info(f"User {username} revoked successfully")
        return {"message": f"Пользователь {username} удален успешно"}
    except subprocess.CalledProcessError as e:
        logger.error(f"Revoke user failed: {e.stderr}")
        return {"error": f"Command failed with exit code {e.returncode}: {e.stderr}"}
    except Exception as e:
        logger.error(f"Revoke user error: {e}")
        return {"error": str(e)}


@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Получаем данные пользователя из БД
    user_data = await get_credentials_from_db(form_data.username)
    if not user_data:
        raise HTTPException(
            status_code=statushttp.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    # Проверяем пароль и статус пользователя
    if not verify_password(form_data.password, user_data["password"]) or user_data["disabled"]:
        raise HTTPException(
            status_code=statushttp.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": form_data.username},
        expires_delta=access_token_expires
    )

    response = RedirectResponse(url="/", status_code=statushttp.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=1800,  # 30 минут
        secure=False,  # Для HTTPS установить True
    )
    return response


@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=statushttp.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token")
    return response