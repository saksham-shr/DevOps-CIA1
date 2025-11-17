import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json

DB_NAME = 'report_generator.db'

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    ''')
    
    # Drafts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS drafts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            draft_name TEXT,
            form_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Login sessions table for device tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_info TEXT,
            ip_address TEXT,
            user_agent TEXT,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_new_device INTEGER DEFAULT 0,
            location_city TEXT,
            location_region TEXT,
            location_country TEXT,
            location_lat REAL,
            location_lon REAL,
            location_isp TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Known devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS known_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_fingerprint TEXT NOT NULL,
            device_info TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, device_fingerprint)
        )
    ''')
    
    # Password reset tokens
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Saved signatures table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS saved_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            signature_name TEXT,
            signature_path TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_default INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Report collaboration table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS report_collaborators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            draft_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT DEFAULT 'editor',
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (draft_id) REFERENCES drafts(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(draft_id, user_id)
        )
    ''')
    
    # Unauthorized access attempts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS unauthorized_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action TEXT,
            location_city TEXT,
            location_country TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def create_user(email, password):
    """Create a new user"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        password_hash = generate_password_hash(password)
        cursor.execute(
            'INSERT INTO users (email, password_hash) VALUES (?, ?)',
            (email, password_hash)
        )
        conn.commit()
        user_id = cursor.lastrowid
        return user_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def verify_user(email, password):
    """Verify user credentials"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ? AND is_active = 1', (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        return dict(user)
    return None

def get_user_by_email(email):
    """Get user by email"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_id(user_id):
    """Get user by ID"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def save_draft(user_id, draft_name, form_data):
    """Save or update a draft"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if draft with same name exists for this user
    cursor.execute(
        'SELECT id FROM drafts WHERE user_id = ? AND draft_name = ?',
        (user_id, draft_name)
    )
    existing = cursor.fetchone()
    
    if existing:
        # Update existing draft
        cursor.execute('''
            UPDATE drafts 
            SET form_data = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (json.dumps(form_data), existing['id']))
        draft_id = existing['id']
    else:
        # Create new draft
        cursor.execute('''
            INSERT INTO drafts (user_id, draft_name, form_data)
            VALUES (?, ?, ?)
        ''', (user_id, draft_name, json.dumps(form_data)))
        draft_id = cursor.lastrowid
    
    conn.commit()
    conn.close()
    return draft_id

def get_user_drafts(user_id):
    """Get all drafts for a user"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM drafts 
        WHERE user_id = ? 
        ORDER BY updated_at DESC
    ''', (user_id,))
    drafts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return drafts

def get_draft(draft_id, user_id):
    """Get a specific draft"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM drafts WHERE id = ? AND user_id = ?',
        (draft_id, user_id)
    )
    draft = cursor.fetchone()
    conn.close()
    return dict(draft) if draft else None

def delete_draft(draft_id, user_id):
    """Delete a draft"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'DELETE FROM drafts WHERE id = ? AND user_id = ?',
        (draft_id, user_id)
    )
    conn.commit()
    conn.close()

def log_login_session(user_id, device_info, ip_address, user_agent, is_new_device, location_data=None):
    """Log a login session with location data"""
    conn = get_db()
    cursor = conn.cursor()
    
    if location_data:
        cursor.execute('''
            INSERT INTO login_sessions (user_id, device_info, ip_address, user_agent, is_new_device,
                location_city, location_region, location_country, location_lat, location_lon, location_isp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, device_info, ip_address, user_agent, is_new_device,
              location_data.get('city'), location_data.get('region'), location_data.get('country'),
              location_data.get('lat'), location_data.get('lon'), location_data.get('isp')))
    else:
        cursor.execute('''
            INSERT INTO login_sessions (user_id, device_info, ip_address, user_agent, is_new_device)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, device_info, ip_address, user_agent, is_new_device))
    
    conn.commit()
    conn.close()

def check_device(user_id, device_fingerprint, device_info):
    """Check if device is known, return (is_known, is_new)"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT * FROM known_devices WHERE user_id = ? AND device_fingerprint = ?',
        (user_id, device_fingerprint)
    )
    device = cursor.fetchone()
    
    if device:
        # Update last seen
        cursor.execute('''
            UPDATE known_devices 
            SET last_seen = CURRENT_TIMESTAMP, device_info = ?
            WHERE id = ?
        ''', (device_info, device['id']))
        conn.commit()
        conn.close()
        return True, False
    else:
        # Add new device
        cursor.execute('''
            INSERT INTO known_devices (user_id, device_fingerprint, device_info)
            VALUES (?, ?, ?)
        ''', (user_id, device_fingerprint, device_info))
        conn.commit()
        conn.close()
        return False, True

def create_password_reset_token(user_id):
    """Create a password reset token"""
    import secrets
    from datetime import timedelta
    
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=24)
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO password_reset_tokens (user_id, token, expires_at)
        VALUES (?, ?, ?)
    ''', (user_id, token, expires_at))
    conn.commit()
    conn.close()
    return token

def verify_reset_token(token):
    """Verify and get user from reset token"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM password_reset_tokens 
        WHERE token = ? AND used = 0 AND expires_at > CURRENT_TIMESTAMP
    ''', (token,))
    token_record = cursor.fetchone()
    conn.close()
    
    if token_record:
        return dict(token_record)
    return None

def use_reset_token(token, new_password):
    """Use a reset token to change password"""
    token_record = verify_reset_token(token)
    if not token_record:
        return False
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Update password
    password_hash = generate_password_hash(new_password)
    cursor.execute(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        (password_hash, token_record['user_id'])
    )
    
    # Mark token as used
    cursor.execute(
        'UPDATE password_reset_tokens SET used = 1 WHERE token = ?',
        (token,)
    )
    
    conn.commit()
    conn.close()
    return True

def get_new_device_logins(admin_email=None):
    """Get all new device login alerts"""
    conn = get_db()
    cursor = conn.cursor()
    
    if admin_email:
        # Get admin user_id
        admin = get_user_by_email(admin_email)
        if not admin:
            conn.close()
            return []
        
        # Get all new device logins
        cursor.execute('''
            SELECT ls.*, u.email 
            FROM login_sessions ls
            JOIN users u ON ls.user_id = u.id
            WHERE ls.is_new_device = 1
            ORDER BY ls.login_time DESC
        ''')
    else:
        cursor.execute('''
            SELECT ls.*, u.email 
            FROM login_sessions ls
            JOIN users u ON ls.user_id = u.id
            WHERE ls.is_new_device = 1
            ORDER BY ls.login_time DESC
        ''')
    
    logins = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logins

def get_all_login_sessions(limit=100):
    """Get all login sessions with location data"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT ls.*, u.email 
        FROM login_sessions ls
        JOIN users u ON ls.user_id = u.id
        ORDER BY ls.login_time DESC
        LIMIT ?
    ''', (limit,))
    sessions = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return sessions

def get_user_login_sessions(user_id, limit=50):
    """Get login sessions for a specific user"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM login_sessions
        WHERE user_id = ?
        ORDER BY login_time DESC
        LIMIT ?
    ''', (user_id, limit))
    sessions = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return sessions

def save_signature(user_id, signature_path, signature_name=None, set_as_default=False):
    """Save a signature for a user"""
    conn = get_db()
    cursor = conn.cursor()
    
    if set_as_default:
        # Unset other defaults for this user
        cursor.execute('UPDATE saved_signatures SET is_default = 0 WHERE user_id = ?', (user_id,))
    
    if not signature_name:
        signature_name = f"Signature {datetime.now().strftime('%Y-%m-%d')}"
    
    cursor.execute('''
        INSERT INTO saved_signatures (user_id, signature_name, signature_path, is_default)
        VALUES (?, ?, ?, ?)
    ''', (user_id, signature_name, signature_path, 1 if set_as_default else 0))
    
    conn.commit()
    signature_id = cursor.lastrowid
    conn.close()
    return signature_id

def get_user_signatures(user_id):
    """Get all saved signatures for a user"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM saved_signatures
        WHERE user_id = ?
        ORDER BY is_default DESC, created_at DESC
    ''', (user_id,))
    signatures = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return signatures

def get_signature(signature_id, user_id):
    """Get a specific signature"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM saved_signatures WHERE id = ? AND user_id = ?',
        (signature_id, user_id)
    )
    signature = cursor.fetchone()
    conn.close()
    return dict(signature) if signature else None

def delete_signature(signature_id, user_id):
    """Delete a saved signature"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'DELETE FROM saved_signatures WHERE id = ? AND user_id = ?',
        (signature_id, user_id)
    )
    conn.commit()
    conn.close()

def set_default_signature(signature_id, user_id):
    """Set a signature as default"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Unset other defaults
    cursor.execute('UPDATE saved_signatures SET is_default = 0 WHERE user_id = ?', (user_id,))
    
    # Set this one as default
    cursor.execute(
        'UPDATE saved_signatures SET is_default = 1 WHERE id = ? AND user_id = ?',
        (signature_id, user_id)
    )
    
    conn.commit()
    conn.close()

def log_unauthorized_access(email, ip_address, user_agent, action, location_data=None):
    """Log unauthorized access attempts"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO unauthorized_access (email, ip_address, user_agent, action, location_city, location_country)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (email, ip_address, user_agent, action, 
          location_data.get('city') if location_data else None,
          location_data.get('country') if location_data else None))
    conn.commit()
    conn.close()

def get_unauthorized_access_logs(limit=100):
    """Get unauthorized access logs"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM unauthorized_access
        ORDER BY attempt_time DESC
        LIMIT ?
    ''', (limit,))
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs

def add_collaborator(draft_id, user_id, role='editor'):
    """Add a collaborator to a draft"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO report_collaborators (draft_id, user_id, role)
            VALUES (?, ?, ?)
        ''', (draft_id, user_id, role))
        conn.commit()
        collaborator_id = cursor.lastrowid
        conn.close()
        return collaborator_id
    except sqlite3.IntegrityError:
        conn.close()
        return None

def get_draft_collaborators(draft_id):
    """Get all collaborators for a draft"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT rc.*, u.email
        FROM report_collaborators rc
        JOIN users u ON rc.user_id = u.id
        WHERE rc.draft_id = ?
    ''', (draft_id,))
    collaborators = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return collaborators

def get_user_collaborative_drafts(user_id):
    """Get all drafts where user is a collaborator"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT d.*, u.email as owner_email
        FROM drafts d
        JOIN report_collaborators rc ON d.id = rc.draft_id
        JOIN users u ON d.user_id = u.id
        WHERE rc.user_id = ?
        ORDER BY d.updated_at DESC
    ''', (user_id,))
    drafts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return drafts

def remove_collaborator(draft_id, user_id):
    """Remove a collaborator from a draft"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        'DELETE FROM report_collaborators WHERE draft_id = ? AND user_id = ?',
        (draft_id, user_id)
    )
    conn.commit()
    conn.close()

def get_draft_by_id(draft_id):
    """Get a draft by ID without user restriction"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM drafts WHERE id = ?', (draft_id,))
    draft = cursor.fetchone()
    conn.close()
    return dict(draft) if draft else None

def can_edit_draft(draft_id, user_id):
    """Check if user can edit a draft (owner or collaborator)"""
    conn = get_db()
    cursor = conn.cursor()
    # Check if owner
    cursor.execute('SELECT user_id FROM drafts WHERE id = ?', (draft_id,))
    draft = cursor.fetchone()
    if draft and draft['user_id'] == user_id:
        conn.close()
        return True
    # Check if collaborator
    cursor.execute(
        'SELECT * FROM report_collaborators WHERE draft_id = ? AND user_id = ?',
        (draft_id, user_id)
    )
    collaborator = cursor.fetchone()
    conn.close()
    return collaborator is not None

def migrate_database():
    """Add location columns to existing login_sessions table if they don't exist"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Check if location columns exist
        cursor.execute("PRAGMA table_info(login_sessions)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'location_city' not in columns:
            print("Migrating database: Adding location columns...")
            cursor.execute('ALTER TABLE login_sessions ADD COLUMN location_city TEXT')
            cursor.execute('ALTER TABLE login_sessions ADD COLUMN location_region TEXT')
            cursor.execute('ALTER TABLE login_sessions ADD COLUMN location_country TEXT')
            cursor.execute('ALTER TABLE login_sessions ADD COLUMN location_lat REAL')
            cursor.execute('ALTER TABLE login_sessions ADD COLUMN location_lon REAL')
            cursor.execute('ALTER TABLE login_sessions ADD COLUMN location_isp TEXT')
            conn.commit()
            print("Database migration completed successfully.")
    except Exception as e:
        print(f"Migration error (may already be migrated): {e}")
        conn.rollback()
    finally:
        conn.close()

# Initialize database on import
init_db()
migrate_database()

