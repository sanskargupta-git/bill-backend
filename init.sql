-- PostgreSQL table for storing bills
CREATE TABLE IF NOT EXISTS bills (
    id SERIAL PRIMARY KEY,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    ocr TEXT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);