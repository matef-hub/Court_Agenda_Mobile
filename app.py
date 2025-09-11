import streamlit as st
import pandas as pd
import sqlite3
import uuid
import threading
import time
import secrets
from datetime import datetime, timedelta
import bcrypt
import urllib.parse
import re
import os
from contextlib import contextmanager

# -----------------------
# Config & Thread Safety
# -----------------------
st.set_page_config(page_title="أجندة المحامي (SQLite)", layout="wide")
DB_NAME = "agenda.db"
DB_LOCK = threading.Lock()
SESSION_TIMEOUT = 3600  # 1 hour in seconds

# ----- RTL & Fonts CSS -----
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Cairo:wght@300;400;600;700&display=swap');
body, .main, .block-container {
    direction: rtl;
    text-align: right;
    font-family: 'Cairo', 'Amiri', sans-serif;
}
.stTitle {font-size:28px; font-weight:700; margin-bottom:6px}
.card {
    background: linear-gradient(180deg, #ffffff 0%, #fbfbfb 100%);
    padding: 14px;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    margin-bottom: 12px;
}
.small-muted {color: #666; font-size:13px}
.mobile-btn {
    width: 100%;
    margin: 2px 0;
    padding: 8px 12px;
    font-size: 14px;
}
@media (max-width: 768px) {
    .stColumns > div {
        min-width: 100% !important;
        flex: 1 1 100% !important;
    }
}
</style>
""", unsafe_allow_html=True)

# -----------------------
# Thread-Safe DB Helpers
# -----------------------
@contextmanager
def get_db_connection():
    """Thread-safe database connection with proper cleanup"""
    with DB_LOCK:
        conn = None
        try:
            conn = sqlite3.connect(DB_NAME, timeout=10.0, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")  # Better for concurrent access
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        except sqlite3.Error as e:
            st.error(f"خطأ في قاعدة البيانات: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

def init_db():
    """Initialize database with proper indexes"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Users table
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT
            )
        """)
        
        # Sessions table
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                case_number TEXT NOT NULL,
                court TEXT NOT NULL,
                chamber TEXT,
                client TEXT NOT NULL,
                date TEXT NOT NULL,
                notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_email) REFERENCES users (email) ON DELETE CASCADE
            )
        """)
        
        # Session tokens table for better security
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_tokens (
                token TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_email) REFERENCES users (email) ON DELETE CASCADE
            )
        """)
        
        # Create indexes for better performance
        c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_date ON sessions(user_email, date)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_date ON sessions(date)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_tokens_user ON user_tokens(user_email)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_tokens_expires ON user_tokens(expires_at)")
        
        conn.commit()

# Initialize database on app start
if not os.path.exists(DB_NAME):
    init_db()

# -----------------------
# Enhanced Validation
# -----------------------
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    if len(password) < 6:
        return False, "كلمة المرور يجب أن تكون 6 أحرف على الأقل"
    if not re.search(r'[A-Za-z]', password):
        return False, "كلمة المرور يجب أن تحتوي على أحرف إنجليزية"
    return True, ""

def sanitize_input(text):
    """Basic input sanitization"""
    if not text:
        return ""
    return str(text).strip()[:500]  # Limit length and strip whitespace

# -----------------------
# Enhanced User Management
# -----------------------
def is_user_locked(email):
    """Check if user account is temporarily locked"""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT locked_until, failed_attempts FROM users WHERE email=?", (email,))
        row = c.fetchone()
        if row and row[0]:
            locked_until = datetime.fromisoformat(row[0])
            if datetime.utcnow() < locked_until:
                return True
        return False

def record_failed_attempt(email):
    """Record failed login attempt and lock if necessary"""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE email=?", (email,))
        
        c.execute("SELECT failed_attempts FROM users WHERE email=?", (email,))
        row = c.fetchone()
        if row and row[0] >= 3:  # Lock after 3 failed attempts
            lock_until = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
            c.execute("UPDATE users SET locked_until=? WHERE email=?", (lock_until, email))
        
        conn.commit()

def clear_failed_attempts(email):
    """Clear failed attempts after successful login"""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=? WHERE email=?", 
                 (datetime.utcnow().isoformat(), email))
        conn.commit()

def add_user(email, name, password_plain):
    email = sanitize_input(email).lower()
    name = sanitize_input(name)
    
    if not email or not name or not password_plain:
        return False
        
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            hashed = bcrypt.hashpw(password_plain.encode(), bcrypt.gensalt()).decode()
            c.execute("INSERT INTO users (email, name, password_hash) VALUES (?,?,?)", 
                     (email, name, hashed))
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False

def verify_user(email, password_plain):
    email = sanitize_input(email).lower()
    
    if is_user_locked(email):
        return False, None, "الحساب مقفل مؤقتاً. حاول مرة أخرى لاحقاً"
        
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT name, password_hash FROM users WHERE email=?", (email,))
        row = c.fetchone()
        
        if row:
            name, stored_hash = row
            if bcrypt.checkpw(password_plain.encode(), stored_hash.encode()):
                clear_failed_attempts(email)
                return True, name, ""
            else:
                record_failed_attempt(email)
                return False, None, "كلمة المرور غير صحيحة"
        else:
            return False, None, "البريد الإلكتروني غير مسجل"

# -----------------------
# Session Token Management
# -----------------------
def create_session_token(user_email):
    """Create secure session token"""
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.utcnow() + timedelta(seconds=SESSION_TIMEOUT)).isoformat()
    
    with get_db_connection() as conn:
        c = conn.cursor()
        # Clean old tokens first
        c.execute("DELETE FROM user_tokens WHERE user_email=? OR expires_at < ?", 
                 (user_email, datetime.utcnow().isoformat()))
        
        # Insert new token
        c.execute("INSERT INTO user_tokens (token, user_email, expires_at) VALUES (?,?,?)",
                 (token, user_email, expires_at))
        conn.commit()
    
    return token

def validate_session_token(token, user_email):
    """Validate session token and check expiration"""
    if not token or not user_email:
        return False
        
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT expires_at FROM user_tokens WHERE token=? AND user_email=?", 
                 (token, user_email))
        row = c.fetchone()
        
        if row:
            expires_at = datetime.fromisoformat(row[0])
            if datetime.utcnow() < expires_at:
                return True
            else:
                # Clean expired token
                c.execute("DELETE FROM user_tokens WHERE token=?", (token,))
                conn.commit()
        
        return False

# -----------------------
# Enhanced Sessions CRUD
# -----------------------
def add_session(user_email, case_number, court, chamber, client, date_str, notes):
    # Sanitize inputs
    case_number = sanitize_input(case_number)
    court = sanitize_input(court)
    chamber = sanitize_input(chamber)
    client = sanitize_input(client)
    notes = sanitize_input(notes)
    
    if not case_number or not court or not client:
        return None
        
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            sid = str(uuid.uuid4())
            c.execute("""
                INSERT INTO sessions (id, user_email, case_number, court, chamber, client, date, notes)
                VALUES (?,?,?,?,?,?,?,?)
            """, (sid, user_email, case_number, court, chamber, client, date_str, notes))
            conn.commit()
            return sid
    except Exception as e:
        st.error(f"خطأ في إضافة الجلسة: {e}")
        return None

@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_sessions(user_email):
    """Get user sessions with caching"""
    try:
        with get_db_connection() as conn:
            df = pd.read_sql_query("""
                SELECT id, case_number, court, chamber, client, date, notes, created_at, updated_at
                FROM sessions 
                WHERE user_email=? 
                ORDER BY date ASC
            """, conn, params=(user_email,))
            
            if not df.empty and "date" in df.columns:
                df["date"] = pd.to_datetime(df["date"], errors="coerce")
            
            return df
    except Exception as e:
        st.error(f"خطأ في استرداد الجلسات: {e}")
        return pd.DataFrame()

def update_session(row_id, user_email, case_number, court, chamber, client, date_str, notes):
    # Sanitize inputs
    case_number = sanitize_input(case_number)
    court = sanitize_input(court)
    chamber = sanitize_input(chamber)
    client = sanitize_input(client)
    notes = sanitize_input(notes)
    
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("""
                UPDATE sessions SET 
                case_number=?, court=?, chamber=?, client=?, date=?, notes=?, updated_at=?
                WHERE id=? AND user_email=?
            """, (case_number, court, chamber, client, date_str, notes, 
                 datetime.utcnow().isoformat(), row_id, user_email))
            conn.commit()
            return c.rowcount > 0
    except Exception as e:
        st.error(f"خطأ في تحديث الجلسة: {e}")
        return False

def delete_session(row_id, user_email):
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM sessions WHERE id=? AND user_email=?", (row_id, user_email))
            conn.commit()
            return c.rowcount > 0
    except Exception as e:
        st.error(f"خطأ في حذف الجلسة: {e}")
        return False

# -----------------------
# Export Functionality
# -----------------------
def export_user_data(user_email):
    """Export user data as CSV for backup"""
    df = get_sessions(user_email)
    if not df.empty:
        # Convert datetime to string for CSV export
        export_df = df.copy()
        if "date" in export_df.columns:
            export_df["date"] = export_df["date"].dt.strftime("%Y-%m-%d")
        return export_df.to_csv(index=False)
    return ""

# -----------------------
# Calendar helper
# -----------------------
def make_google_calendar_url(title, start_date_str, details=""):
    try:
        d = datetime.fromisoformat(start_date_str)
        start = d.strftime("%Y%m%d")
        end = (d + timedelta(days=1)).strftime("%Y%m%d")
    except:
        start = start_date_str.replace("-","")
        end = start
    text = urllib.parse.quote(title)
    details_enc = urllib.parse.quote(details)
    dates = f"{start}/{end}"
    url = f"https://www.google.com/calendar/render?action=TEMPLATE&text={text}&dates={dates}&details={details_enc}"
    return url

# -----------------------
# Enhanced UI
# -----------------------
st.markdown('<div class="stTitle">📅 أجندة المحامي (SQLite)</div>', unsafe_allow_html=True)
st.write("تطبيق لحفظ الجلسات مع حساب منفصل لكل محامي — يعمل بقاعدة بيانات SQLite محسنة.")

# Initialize session state with proper defaults
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_email" not in st.session_state:
    st.session_state.user_email = None
if "user_name" not in st.session_state:
    st.session_state.user_name = None
if "session_token" not in st.session_state:
    st.session_state.session_token = None

# Validate existing session
if (st.session_state.logged_in and st.session_state.session_token and 
    st.session_state.user_email):
    if not validate_session_token(st.session_state.session_token, st.session_state.user_email):
        st.session_state.logged_in = False
        st.session_state.user_email = None
        st.session_state.user_name = None
        st.session_state.session_token = None
        st.warning("انتهت مدة الجلسة. يرجى تسجيل الدخول مرة أخرى.")

# Authentication UI
if not st.session_state.logged_in:
    choice = st.radio("الحالة", ("تسجيل دخول","إنشاء حساب"))
    
    if choice == "إنشاء حساب":
        with st.form("signup_form", clear_on_submit=True):
            su_name = st.text_input("الاسم بالكامل")
            su_email = st.text_input("البريد الإلكتروني")
            su_password = st.text_input("كلمة المرور", type="password", 
                                      help="6 أحرف على الأقل مع أحرف إنجليزية")
            su_password2 = st.text_input("تأكيد كلمة المرور", type="password")
            submitted = st.form_submit_button("إنشاء حساب", use_container_width=True)
            
            if submitted:
                if not su_name or not su_email or not su_password:
                    st.error("من فضلك املأ كل الحقول.")
                elif not validate_email(su_email):
                    st.error("صيغة البريد الإلكتروني غير صحيحة.")
                elif su_password != su_password2:
                    st.error("كلمتا المرور غير متطابقتين.")
                else:
                    valid_pass, pass_msg = validate_password(su_password)
                    if not valid_pass:
                        st.error(pass_msg)
                    else:
                        with st.spinner("جاري إنشاء الحساب..."):
                            if add_user(su_email, su_name, su_password):
                                st.success("تم إنشاء الحساب! يمكنك الآن تسجيل الدخول.")
                                time.sleep(2)
                                st.rerun()
                            else:
                                st.error("هذا البريد مسجل بالفعل.")
    else:
        with st.form("login_form", clear_on_submit=True):
            li_email = st.text_input("البريد الإلكتروني")
            li_password = st.text_input("كلمة المرور", type="password")
            submitted = st.form_submit_button("تسجيل دخول", use_container_width=True)
            
            if submitted:
                with st.spinner("جاري التحقق..."):
                    ok, name, error_msg = verify_user(li_email, li_password)
                    if ok:
                        # Create session token
                        token = create_session_token(li_email)
                        st.session_state.logged_in = True
                        st.session_state.user_email = li_email
                        st.session_state.user_name = name
                        st.session_state.session_token = token
                        st.success(f"مرحباً {name} — تم تسجيل الدخول.")
                        # Clear cached data for new user
                        st.cache_data.clear()
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(error_msg or "فشل تسجيل الدخول")

st.divider()

# Main application for logged-in users
if st.session_state.logged_in:
    user_email = st.session_state.user_email
    user_name = st.session_state.user_name
    
    # Header with user info and logout
    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader(f"أجندتك — {user_name}")
    with col2:
        if st.button("🚪 تسجيل الخروج", use_container_width=True):
            # Clean up session token
            if st.session_state.session_token:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute("DELETE FROM user_tokens WHERE token=?", (st.session_state.session_token,))
                    conn.commit()
            
            st.session_state.logged_in = False
            st.session_state.user_email = None
            st.session_state.user_name = None
            st.session_state.session_token = None
            st.cache_data.clear()
            st.rerun()

    # Add session form
    with st.expander("➕ إضافة جلسة جديدة", expanded=False):
        with st.form("add_session_form", clear_on_submit=True):
            col1, col2 = st.columns(2)
            with col1:
                case_number = st.text_input("رقم القضية*", max_chars=100)
                court = st.text_input("المحكمة / الجهة*", max_chars=200)
            with col2:
                chamber = st.text_input("الدائرة / القلم (اختياري)", max_chars=100)
                client = st.text_input("اسم الموكل*", max_chars=200)
            
            col3, col4 = st.columns(2)
            with col3:
                date = st.date_input("تاريخ الجلسة*", value=datetime.now().date())
            with col4:
                st.write("")  # Spacer
            
            notes = st.text_area("ملاحظات (اختياري)", max_chars=1000, height=100)
            
            sub = st.form_submit_button("📅 إضافة الجلسة", use_container_width=True)
            if sub:
                if not case_number or not court or not client:
                    st.error("من فضلك املأ الحقول المطلوبة (*)")
                else:
                    with st.spinner("جاري الإضافة..."):
                        sid = add_session(user_email, case_number, court, chamber, client, 
                                        date.isoformat(), notes)
                        if sid:
                            st.success("تمت إضافة الجلسة بنجاح!")
                            st.cache_data.clear()  # Clear cache to show new data
                            time.sleep(1)
                            st.rerun()

    # Display sessions
    with st.spinner("جاري تحميل الجلسات..."):
        df = get_sessions(user_email)
    
    if df.empty:
        st.info("لا توجد جلسات مسجلة بعد.")
    else:
        # Export data section
        st.subheader("📥 تصدير البيانات")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("تحميل نسخة احتياطية", use_container_width=True):
                csv_data = export_user_data(user_email)
                if csv_data:
                    st.download_button(
                        label="📄 تحميل ملف CSV",
                        data=csv_data,
                        file_name=f"court_sessions_{user_email}_{datetime.now().strftime('%Y%m%d')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
                else:
                    st.error("لا توجد بيانات للتصدير")
        
        st.divider()
        
        # Upcoming sessions
        today = datetime.now().date()
        upcoming = df[df["date"].dt.date >= today] if not df.empty else pd.DataFrame()
        
        st.subheader("📅 الجلسات القادمة")
        if upcoming.empty:
            st.info("لا توجد جلسات قادمة.")
        else:
            for _, row in upcoming.iterrows():
                date_display = row["date"].strftime("%Y-%m-%d") if not pd.isna(row["date"]) else str(row["date"])
                days_until = (row["date"].date() - today).days if not pd.isna(row["date"]) else 0
                
                # Color coding based on urgency
                if days_until == 0:
                    urgency_color = "#ff4444"  # Red for today
                    urgency_text = "اليوم"
                elif days_until == 1:
                    urgency_color = "#ff8800"  # Orange for tomorrow
                    urgency_text = "غداً"
                elif days_until <= 7:
                    urgency_color = "#ffaa00"  # Yellow for this week
                    urgency_text = f"خلال {days_until} أيام"
                else:
                    urgency_color = "#00aa00"  # Green for later
                    urgency_text = f"خلال {days_until} يوماً"
                
                st.markdown(f"""
                <div class='card' style='border-left: 4px solid {urgency_color};'>
                    <div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;'>
                        <h4 style='margin: 0; color: {urgency_color};'>📅 {date_display}</h4>
                        <span style='background: {urgency_color}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px;'>{urgency_text}</span>
                    </div>
                    <p><b>📌 رقم القضية:</b> {row['case_number']}</p>
                    <p><b>🏛️ المحكمة:</b> {row['court']} <span class='small-muted'>({row['chamber'] or 'غير محدد'})</span></p>
                    <p><b>👤 الموكل:</b> {row['client']}</p>
                    <p class='small-muted'><b>ملاحظات:</b> {row['notes'] or 'لا توجد ملاحظات'}</p>
                </div>
                """, unsafe_allow_html=True)
                
                # Action buttons - mobile-friendly layout
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("📅 للتقويم", key=f"cal_{row['id']}", use_container_width=True):
                        title = f"جلسة قضية {row['case_number']} — {row['court']}"
                        details = f"دائرة: {row['chamber'] or 'غير محدد'}\\nموكل: {row['client']}\\nملاحظات: {row['notes'] or 'لا توجد'}"
                        url = make_google_calendar_url(title, row["date"].strftime("%Y-%m-%d"), details=details)
                        st.markdown(f"[🔗 افتح Google Calendar لإضافتها]({url})")
                
                with col2:
                    if st.button("✏️ تعديل", key=f"edit_{row['id']}", use_container_width=True):
                        st.session_state[f"edit_mode_{row['id']}"] = True
                        st.rerun()
                
                with col3:
                    if st.button("🗑️ حذف", key=f"del_{row['id']}", use_container_width=True):
                        st.session_state[f"confirm_delete_{row['id']}"] = True
                        st.rerun()
                
                # Edit form (appears when edit button is clicked)
                if st.session_state.get(f"edit_mode_{row['id']}", False):
                    with st.form(f"edit_form_{row['id']}", clear_on_submit=True):
                        st.subheader("✏️ تعديل الجلسة")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            en_case = st.text_input("رقم القضية", value=row["case_number"], max_chars=100)
                            en_court = st.text_input("المحكمة", value=row["court"], max_chars=200)
                        with col2:
                            en_chamber = st.text_input("الدائرة", value=row["chamber"] or "", max_chars=100)
                            en_client = st.text_input("الموكل", value=row["client"], max_chars=200)
                        
                        en_date = st.date_input("تاريخ الجلسة", 
                                              value=row["date"].date() if not pd.isna(row["date"]) else today)
                        en_notes = st.text_area("ملاحظات", value=row["notes"] or "", max_chars=1000)
                        
                        col_save, col_cancel = st.columns(2)
                        with col_save:
                            e_sub = st.form_submit_button("💾 حفظ التغييرات", use_container_width=True)
                        with col_cancel:
                            e_cancel = st.form_submit_button("❌ إلغاء", use_container_width=True)
                        
                        if e_sub:
                            if not en_case or not en_court or not en_client:
                                st.error("من فضلك املأ الحقول المطلوبة")
                            else:
                                with st.spinner("جاري الحفظ..."):
                                    if update_session(row["id"], user_email, en_case, en_court, 
                                                    en_chamber, en_client, en_date.isoformat(), en_notes):
                                        st.success("تم تحديث الجلسة بنجاح!")
                                        st.session_state[f"edit_mode_{row['id']}"] = False
                                        st.cache_data.clear()
                                        time.sleep(1)
                                        st.rerun()
                                    else:
                                        st.error("فشل في تحديث الجلسة")
                        
                        if e_cancel:
                            st.session_state[f"edit_mode_{row['id']}"] = False
                            st.rerun()
                
                # Delete confirmation (appears when delete button is clicked)
                if st.session_state.get(f"confirm_delete_{row['id']}", False):
                    st.warning(f"⚠️ هل أنت متأكد من حذف جلسة القضية رقم {row['case_number']}؟")
                    col_confirm, col_cancel = st.columns(2)
                    
                    with col_confirm:
                        if st.button("✅ نعم، احذف", key=f"confirm_del_{row['id']}", use_container_width=True):
                            with st.spinner("جاري الحذف..."):
                                if delete_session(row["id"], user_email):
                                    st.success("تم حذف الجلسة بنجاح!")
                                    st.session_state[f"confirm_delete_{row['id']}"] = False
                                    st.cache_data.clear()
                                    time.sleep(1)
                                    st.rerun()
                                else:
                                    st.error("فشل في حذف الجلسة")
                    
                    with col_cancel:
                        if st.button("❌ إلغاء", key=f"cancel_del_{row['id']}", use_container_width=True):
                            st.session_state[f"confirm_delete_{row['id']}"] = False
                            st.rerun()
        
        st.divider()
        
        # All sessions table
        st.subheader("📊 كل الجلسات")
        
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            filter_court = st.selectbox("فلترة حسب المحكمة", 
                                      options=["الكل"] + sorted(df["court"].dropna().unique().tolist()),
                                      key="court_filter")
        with col2:
            filter_client = st.selectbox("فلترة حسب الموكل",
                                       options=["الكل"] + sorted(df["client"].dropna().unique().tolist()),
                                       key="client_filter")
        
        # Apply filters
        filtered_df = df.copy()
        if filter_court != "الكل":
            filtered_df = filtered_df[filtered_df["court"] == filter_court]
        if filter_client != "الكل":
            filtered_df = filtered_df[filtered_df["client"] == filter_client]
        
        # Prepare display table
        if not filtered_df.empty:
            display_df = filtered_df[["date", "case_number", "court", "chamber", "client", "notes"]].copy()
            display_df = display_df.sort_values("date", ascending=False)  # Most recent first
            
            # Format date for display
            display_df["التاريخ"] = display_df["date"].dt.strftime("%Y-%m-%d")
            display_df["رقم القضية"] = display_df["case_number"]
            display_df["المحكمة"] = display_df["court"]
            display_df["الدائرة"] = display_df["chamber"].fillna("غير محدد")
            display_df["الموكل"] = display_df["client"]
            display_df["ملاحظات"] = display_df["notes"].fillna("لا توجد")
            
            # Select only Arabic columns for display
            final_df = display_df[["التاريخ", "رقم القضية", "المحكمة", "الدائرة", "الموكل", "ملاحظات"]]
            
            st.dataframe(
                final_df,
                use_container_width=True,
                height=400,
                hide_index=True
            )
            
            # Statistics
            st.subheader("📈 إحصائيات")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("إجمالي الجلسات", len(filtered_df))
            
            with col2:
                upcoming_count = len(filtered_df[filtered_df["date"].dt.date >= today])
                st.metric("الجلسات القادمة", upcoming_count)
            
            with col3:
                past_count = len(filtered_df[filtered_df["date"].dt.date < today])
                st.metric("الجلسات السابقة", past_count)
            
            with col4:
                unique_courts = filtered_df["court"].nunique()
                st.metric("المحاكم المختلفة", unique_courts)
        
        else:
            st.info("لا توجد جلسات تطابق المرشحات المحددة.")

    # Footer with app info
    st.divider()
    st.markdown("""
    <div style='text-align: center; color: #666; font-size: 12px; padding: 20px 0;'>
        <p>📱 أجندة المحامي - نسخة محسنة مع SQLite</p>
        <p>🔒 جميع البيانات محفوظة بشكل آمن | 🚀 محسن للأداء</p>
        <p style='margin-top: 10px;'>
            💡 <strong>نصيحة:</strong> قم بتصدير نسخة احتياطية من بياناتك بانتظام
        </p>
    </div>
    """, unsafe_allow_html=True)

else:
    # Welcome message for non-logged users
    st.markdown("""
    <div style='text-align: center; padding: 40px 20px;'>
        <h3>⚖️ مرحباً بك في أجندة المحامي</h3>
        <p style='font-size: 16px; color: #666; margin: 20px 0;'>
            نظام آمن ومحسن لإدارة جلسات المحاكم والقضايا
        </p>
        <div style='display: flex; justify-content: center; gap: 20px; margin: 30px 0; flex-wrap: wrap;'>
            <div style='background: #f8f9fa; padding: 15px; border-radius: 8px; min-width: 200px;'>
                <h4>🔒 أمان عالي</h4>
                <p style='font-size: 14px;'>تشفير كلمات المرور وحماية البيانات</p>
            </div>
            <div style='background: #f8f9fa; padding: 15px; border-radius: 8px; min-width: 200px;'>
                <h4>📱 متوافق مع الجوال</h4>
                <p style='font-size: 14px;'>واجهة محسنة لجميع الأجهزة</p>
            </div>
            <div style='background: #f8f9fa; padding: 15px; border-radius: 8px; min-width: 200px;'>
                <h4>📅 تقويم Google</h4>
                <p style='font-size: 14px;'>إضافة مباشرة للتقويم</p>
            </div>
        </div>
        <p style='color: #28a745; font-weight: bold;'>
            الرجاء تسجيل الدخول أو إنشاء حساب للبدء
        </p>
    </div>
    """, unsafe_allow_html=True)