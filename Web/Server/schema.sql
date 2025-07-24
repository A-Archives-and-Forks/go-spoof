CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  pass TEXT NOT NULL,
  reset_token TEXT,
  reset_expires DATETIME
);

CREATE TABLE IF NOT EXISTS uploads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL,
  originalname TEXT NOT NULL,
  storedname TEXT NOT NULL,
  uploaded_at TEXT NOT NULL,
  user_id INTEGER NOT NULL
);