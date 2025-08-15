import aiosqlite
import logging

DB_PATH = "/app/db/connections.db"
logger = logging.getLogger(__name__)

async def init_db():
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute('''
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    common_name TEXT NOT NULL,
                    connected_at TEXT NOT NULL,
                    disconnected_at TEXT,
                    duration_minutes INTEGER,
                    bytes_received REAL,
                    bytes_sent REAL,
                    last_updated TEXT
                )
            ''')
            await db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    common_name TEXT PRIMARY KEY,
                    email TEXT,
                    description TEXT
                )
            ''')
            await db.commit()
            logger.info(f"Database initialized at {DB_PATH}")
    except Exception as e:
        logger.error(f"Failed to initialize database at {DB_PATH}: {e}")
        raise

async def add_connection(common_name, connected_at, last_updated):
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT INTO connections (common_name, connected_at, last_updated) VALUES (?, ?, ?)",
                (common_name, connected_at, last_updated)
            )
            await db.commit()
            logger.info(f"Added connection for {common_name}")
    except Exception as e:
        logger.error(f"Error adding connection for {common_name}: {e}")

async def update_connection_disconnect(common_name, disconnected_at, duration_minutes, bytes_received, bytes_sent):
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE connections SET disconnected_at = ?, duration_minutes = ?, bytes_received = ?, bytes_sent = ?, last_updated = ? WHERE common_name = ? AND disconnected_at IS NULL",
                (disconnected_at, duration_minutes, bytes_received, bytes_sent, disconnected_at, common_name)
            )
            await db.commit()
            logger.info(f"Updated disconnect for {common_name}: {disconnected_at}")
    except Exception as e:
        logger.error(f"Error updating disconnect for {common_name}: {e}")

async def update_connection_traffic(common_name, bytes_received, bytes_sent, last_updated):
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE connections SET bytes_received = ?, bytes_sent = ?, last_updated = ? WHERE common_name = ? AND disconnected_at IS NULL",
                (bytes_received, bytes_sent, last_updated, common_name)
            )
            await db.commit()
            logger.info(f"Updated traffic for {common_name}: received={bytes_received}, sent={bytes_sent}")
    except Exception as e:
        logger.error(f"Error updating traffic for {common_name}: {e}")

async def get_all_connections():
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM connections") as cursor:
                return [dict(row) for row in await cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error fetching connections: {e}")
        return []

async def add_user(common_name, email, description):
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT OR REPLACE INTO users (common_name, email, description) VALUES (?, ?, ?)",
                (common_name, email, description)
            )
            await db.commit()
            logger.info(f"Added user {common_name}")
    except Exception as e:
        logger.error(f"Error adding user {common_name}: {e}")

async def remove_user(common_name):
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("DELETE FROM users WHERE common_name = ?", (common_name,))
            await db.commit()
            logger.info(f"Removed user {common_name}")
    except Exception as e:
        logger.error(f"Error removing user {common_name}: {e}")

async def get_all_users_from_db():
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM users") as cursor:
                return [dict(row) for row in await cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return []