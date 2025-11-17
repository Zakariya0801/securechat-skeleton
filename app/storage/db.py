"""MySQL users table + salted hashing (no chat storage)."""
import mysql.connector
from mysql.connector import Error
import hashlib
import os

class DatabaseManager:
    """Manages MySQL database connection and user operations"""
    
    def __init__(self, host='localhost', user='root', password='', database='securechat'):
        """Initialize database connection parameters"""
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.connection = None
    
    def connect(self):
        """Establish connection to MySQL database"""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database
            )
            if self.connection.is_connected():
                return True
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
            return False
    
    def disconnect(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
    
    def create_database(self):
        """Create securechat database if it doesn't exist"""
        try:
            conn = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password
            )
            cursor = conn.cursor()
            cursor.execute("CREATE DATABASE IF NOT EXISTS securechat")
            cursor.close()
            conn.close()
            return True
        except Error as e:
            print(f"Error creating database: {e}")
            return False
    
    def create_users_table(self):
        """Create users table with email, username, salt, and password hash"""
        try:
            cursor = self.connection.cursor()
            create_table_query = """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                username VARCHAR(255) NOT NULL UNIQUE,
                salt VARBINARY(16) NOT NULL,
                pwd_hash CHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
            cursor.execute(create_table_query)
            self.connection.commit()
            cursor.close()
            return True
        except Error as e:
            print(f"Error creating users table: {e}")
            return False
    
    def register_user(self, email, username, password):
        """
        Register new user with salted password hash
        Returns: (success: bool, message: str, salt: bytes or None)
        """
        try:
            cursor = self.connection.cursor()
            
            # Check if user already exists
            check_query = "SELECT email FROM users WHERE email = %s OR username = %s"
            cursor.execute(check_query, (email, username))
            if cursor.fetchone():
                cursor.close()
                return False, "User with this email or username already exists", None
            
            # Generate random salt (16 bytes)
            salt = os.urandom(16)
            
            # Compute salted hash: SHA256(salt || password)
            pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
            
            # Insert user into database
            insert_query = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
            cursor.execute(insert_query, (email, username, salt, pwd_hash))
            self.connection.commit()
            cursor.close()
            
            return True, "User registered successfully", salt
            
        except Error as e:
            return False, f"Database error: {e}", None
    
    def authenticate_user(self, email, password):
        """
        Authenticate user by verifying salted password hash
        Returns: (success: bool, message: str, username: str or None)
        """
        try:
            cursor = self.connection.cursor()
            
            # Retrieve user data
            query = "SELECT username, salt, pwd_hash FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            cursor.close()
            
            if not result:
                return False, "User not found", None
            
            username, salt, stored_hash = result
            
            # Compute hash with provided password
            computed_hash = hashlib.sha256(salt + password.encode()).hexdigest()
            
            # Verify hash
            if computed_hash == stored_hash:
                return True, "Authentication successful", username
            else:
                return False, "Invalid password", None
                
        except Error as e:
            return False, f"Database error: {e}", None
    
    def get_user_salt(self, email):
        """
        Retrieve salt for a user
        Returns: salt as bytes or None
        """
        try:
            cursor = self.connection.cursor()
            query = "SELECT salt FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                return result[0]
            return None
            
        except Error as e:
            print(f"Database error: {e}")
            return None

def initialize_database(host='localhost', user='scuser', password='scpass', database='securechat'):
    """
    Initialize database and create necessary tables
    Returns: DatabaseManager instance
    """
    db = DatabaseManager(host, user, password, database)
    db.create_database()
    if db.connect():
        db.create_users_table()
        return db
    return None
