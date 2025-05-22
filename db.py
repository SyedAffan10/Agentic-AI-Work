import sqlite3

# Database setup functions
def initialize_database():
    """Create the SQLite database and required tables if they don't exist."""
    conn = sqlite3.connect('security_workflow.db')
    cursor = conn.cursor()
    
    # Create table for storing workflow results
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS workflow_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        result_json TEXT NOT NULL
    )
    ''')
    
    conn.commit()
    conn.close()
    
    print("Database initialized successfully")

if __name__ == "__main__":
    initialize_database()