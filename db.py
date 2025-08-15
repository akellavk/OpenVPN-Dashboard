import os

import aiosqlite

DB_PATH = "/app/connections.db"

async def exist_db():
    if os.path.exists(DB_PATH):
        return True
    else:
        return False

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            common_name TEXT NOT NULL,
            connected_at TEXT NOT NULL,
            disconnected_at TEXT,
            duration_minutes INTEGER,
            bytes_received REAL DEFAULT 0,
            bytes_sent REAL DEFAULT 0
        )
        """)
        await db.commit()

async def add_connection(common_name, connected_at):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        INSERT INTO connections (common_name, connected_at)
        VALUES (?, ?)
        """, (common_name, connected_at))
        await db.commit()

async def update_connection_disconnect(common_name, disconnected_at, duration_minutes, bytes_received, bytes_sent):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        UPDATE connections
        SET disconnected_at = ?, duration_minutes = ?, bytes_received = ?, bytes_sent = ?
        WHERE common_name = ? AND disconnected_at IS NULL
        """, (disconnected_at, duration_minutes, bytes_received, bytes_sent, common_name))
        await db.commit()

async def update_connection_traffic(common_name, bytes_received, bytes_sent):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        UPDATE connections
        SET bytes_received = ?, bytes_sent = ?
        WHERE common_name = ? AND disconnected_at IS NULL
        """, (bytes_received, bytes_sent, common_name))
        await db.commit()

async def get_all_connections():
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT * FROM connections ORDER BY id DESC")
        rows = await cursor.fetchall()
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in rows]
