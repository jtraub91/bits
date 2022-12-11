"""
DB stuff
"""
import logging
import sqlite3

log = logging.getLogger("db")

connection = sqlite3.connect(".bits/bits.db")
cursor = connection.cursor()

DB_TABLES = ["wallet"]


def init_schema():
    cursor.execute("CREATE TABLE wallet(name, type)")


def detect_schema():
    """
    Return True if all DB_TABLES exist, else False
    """
    res = cursor.execute("SELECT name FROM sqlite_master")
    tables = [result[0] for result in res.fetchall()]
    if set(tables) == set(DB_TABLES):
        return True
    return False
