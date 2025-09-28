-- Shops table
CREATE TABLE IF NOT EXISTS shops (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  shop_id INTEGER REFERENCES shops(id),
  role TEXT DEFAULT 'salesman',
  created_at TIMESTAMP DEFAULT NOW()
);

-- Items table
CREATE TABLE IF NOT EXISTS items (
  id SERIAL PRIMARY KEY,
  shop_id INTEGER REFERENCES shops(id),
  name TEXT NOT NULL,
  barcode TEXT UNIQUE,
  quantity INTEGER DEFAULT 0,
  price NUMERIC(12,2),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Inventory log (for OCR upserts)
CREATE TABLE IF NOT EXISTS inventory_logs (
  id SERIAL PRIMARY KEY,
  item_id INTEGER REFERENCES items(id),
  ocr_data JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);
