"""
Fleet Manager Enterprise
========================
A Streamlit-based vehicle rental / fleet management system.
PostgreSQL version for Railway deployment.
"""

import streamlit as st
import os
import psycopg2
import psycopg2.extras
import pandas as pd
import bcrypt
import uuid
import logging
import io
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# =============================================================================
# SYSTEM MONITORING & ENGINE CONFIGURATION
# =============================================================================

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")

st.set_page_config(page_title="Fleet Manager Enterprise", layout="wide")

DATABASE_URL = os.environ.get("DATABASE_URL", "")


# =============================================================================
# CRYPTOGRAPHIC SECURITY LAYER (BCRYPT)
# =============================================================================

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


# =============================================================================
# DATABASE ENGINE & LIFECYCLE MANAGEMENT
# =============================================================================

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    conn.autocommit = False
    return conn

@st.cache_resource
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('Admin', 'General')),
                is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1))
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vehicles (
                reg_number TEXT PRIMARY KEY,
                model TEXT NOT NULL,
                color TEXT,
                vehicle_type TEXT NOT NULL DEFAULT 'Standard Car',
                status TEXT NOT NULL DEFAULT 'Available' CHECK(status IN ('Available', 'Rented', 'In Shop'))
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS customers (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                phone TEXT UNIQUE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hires (
                hire_id TEXT PRIMARY KEY,
                reg_number TEXT,
                customer_name TEXT,
                customer_phone TEXT,
                national_id_number TEXT,
                national_id_image BYTEA,
                date_out TEXT,
                date_returned TEXT,
                location TEXT,
                rate_per_day REAL,
                days INTEGER,
                amount_due REAL,
                amount_paid REAL,
                balance REAL,
                payment_method TEXT,
                received_by TEXT,
                is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
                FOREIGN KEY(reg_number) REFERENCES vehicles(reg_number) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS expenses (
                id SERIAL PRIMARY KEY,
                reg_number TEXT,
                category TEXT,
                description TEXT,
                cost REAL CHECK(cost >= 0),
                FOREIGN KEY(reg_number) REFERENCES vehicles(reg_number) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_expenses (
                id SERIAL PRIMARY KEY,
                date TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                cost REAL NOT NULL CHECK(cost >= 0),
                logged_by TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                timestamp TEXT,
                username TEXT,
                action TEXT
            )
        ''')

        # Migration safety: add columns if missing
        for col_check in [
            ("users", "is_active", "ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1"),
            ("vehicles", "status", "ALTER TABLE vehicles ADD COLUMN status TEXT NOT NULL DEFAULT 'Available'"),
            ("vehicles", "vehicle_type", "ALTER TABLE vehicles ADD COLUMN vehicle_type TEXT NOT NULL DEFAULT 'Standard Car'"),
            ("hires", "is_active", "ALTER TABLE hires ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1"),
        ]:
            tbl, col, alter_sql = col_check
            cursor.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name=%s AND column_name=%s",
                (tbl, col)
            )
            if cursor.fetchone() is None:
                cursor.execute(alter_sql)

        # Permanently remove ghost/seed rows that contain literal column-name strings.
        # This runs on every startup, so Railway restarts cannot re-introduce them.
        cursor.execute("""
            DELETE FROM audit_log
            WHERE username = 'username'
               OR action = 'action'
               OR timestamp = 'timestamp'
               OR (username IS NULL AND action IS NULL)
        """)
        cursor.execute("""
            DELETE FROM users
            WHERE username = 'username'
               OR role = 'role'
               OR username IS NULL
               OR username = ''
        """)

        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()["count"] == 0:
            admin_pass = os.environ.get("ADMIN_PASSWORD", "admin123")
            staff_pass = os.environ.get("STAFF_PASSWORD", "staff123")
            cursor.execute("INSERT INTO users VALUES ('McDonald', %s, 'Admin', 1)", (hash_password(admin_pass),))
            cursor.execute("INSERT INTO users VALUES ('StaffUser', %s, 'General', 1)", (hash_password(staff_pass),))
            cursor.execute(
                "INSERT INTO audit_log (id, timestamp, username, action) VALUES (%s, %s, 'System', 'Database initialised.')",
                (str(uuid.uuid4()), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )

        conn.commit()
    finally:
        conn.close()

init_db()


# =============================================================================
# OPERATIONAL AUDITING & UTILITIES
# =============================================================================

def log_action(user: str, action: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Provide id as UUID string — works whether the column is TEXT or SERIAL
        entry_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO audit_log (id, timestamp, username, action) VALUES (%s, %s, %s, %s)",
            (entry_id, timestamp, user, action)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logging.warning(f"Audit log write failed: {e}")

def generate_hire_id() -> str:
    return f"H{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"

def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')


def generate_pdf_report(
    title: str,
    subtitle: str,
    df_hires: pd.DataFrame,
    df_expenses: pd.DataFrame,
    df_admin_exp: pd.DataFrame,
    scope_label: str,
    time_label: str,
) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm, topMargin=20*mm, bottomMargin=20*mm,
    )
    styles = getSampleStyleSheet()
    heading_style = ParagraphStyle("Heading", parent=styles["Heading1"], fontSize=16, textColor=colors.HexColor("#1a1a2e"), spaceAfter=4, alignment=TA_CENTER)
    sub_style = ParagraphStyle("Sub", parent=styles["Normal"], fontSize=9, textColor=colors.grey, spaceAfter=2, alignment=TA_CENTER)
    section_style = ParagraphStyle("Section", parent=styles["Heading2"], fontSize=11, textColor=colors.HexColor("#16213e"), spaceBefore=10, spaceAfter=4)
    cell_style = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=7.5, leading=10)
    HEADER_BG  = colors.HexColor("#16213e")
    ALT_ROW_BG = colors.HexColor("#f0f4f8")
    BORDER_CLR = colors.HexColor("#cccccc")

    def make_table(df: pd.DataFrame, col_widths=None) -> Table:
        headers = [Paragraph(f"<b>{c}</b>", ParagraphStyle("Hdr", parent=styles["Normal"], fontSize=7.5, textColor=colors.white, alignment=TA_CENTER)) for c in df.columns]
        rows = [headers]
        for i, (_, row) in enumerate(df.iterrows()):
            rows.append([Paragraph(str(v) if v is not None else "—", cell_style) for v in row.values])
        page_width = A4[0] - 30*mm
        if col_widths is None:
            col_widths = [page_width / len(df.columns)] * len(df.columns)
        tbl = Table(rows, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), HEADER_BG),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTSIZE", (0,0), (-1,-1), 7.5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, ALT_ROW_BG]),
            ("GRID", (0,0), (-1,-1), 0.4, BORDER_CLR),
            ("TOPPADDING", (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ("LEFTPADDING", (0,0), (-1,-1), 4),
            ("RIGHTPADDING", (0,0), (-1,-1), 4),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ]))
        return tbl

    story = []
    story.append(Paragraph("Fleet Manager Enterprise", heading_style))
    story.append(Paragraph(f"{title}", sub_style))
    story.append(Paragraph(f"Scope: {scope_label}  |  Period: {time_label}  |  Generated: {datetime.now().strftime('%d-%m-%Y %H:%M')}", sub_style))
    story.append(Spacer(1, 8*mm))

    total_due    = df_hires["amount_due"].sum()    if not df_hires.empty else 0
    total_paid   = df_hires["amount_paid"].sum()   if not df_hires.empty else 0
    total_bal    = df_hires["balance"].sum()        if not df_hires.empty else 0
    total_veh_ex = df_expenses["cost"].sum()        if not df_expenses.empty else 0
    total_adm_ex = df_admin_exp["cost"].sum()       if not df_admin_exp.empty else 0

    summary_data = [
        [Paragraph("<b>Gross Revenue</b>", cell_style), Paragraph(f"MWK {total_due:,.0f}", cell_style),
         Paragraph("<b>Collected</b>", cell_style), Paragraph(f"MWK {total_paid:,.0f}", cell_style),
         Paragraph("<b>Outstanding</b>", cell_style), Paragraph(f"MWK {total_bal:,.0f}", cell_style)],
        [Paragraph("<b>Vehicle Costs</b>", cell_style), Paragraph(f"MWK {total_veh_ex:,.0f}", cell_style),
         Paragraph("<b>Admin Costs</b>", cell_style), Paragraph(f"MWK {total_adm_ex:,.0f}", cell_style),
         Paragraph("<b>Net Margin</b>", cell_style), Paragraph(f"MWK {total_paid - total_veh_ex - total_adm_ex:,.0f}", cell_style)],
    ]
    page_w = A4[0] - 30*mm
    summary_tbl = Table(summary_data, colWidths=[page_w/6]*6)
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#e8edf2")),
        ("BACKGROUND", (2,0), (2,-1), colors.HexColor("#e8edf2")),
        ("BACKGROUND", (4,0), (4,-1), colors.HexColor("#e8edf2")),
        ("GRID", (0,0), (-1,-1), 0.4, BORDER_CLR),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(summary_tbl)
    story.append(Spacer(1, 6*mm))

    if not df_hires.empty:
        story.append(Paragraph("Rental Invoice Ledger", section_style))
        display_cols = ["hire_id","customer_name","reg_number","date_out","date_returned","days","rate_per_day","amount_due","amount_paid","balance","payment_method"]
        display_cols = [c for c in display_cols if c in df_hires.columns]
        df_h = df_hires[display_cols].copy()
        df_h["date_out"]      = df_h["date_out"].apply(fmt_date)
        df_h["date_returned"] = df_h["date_returned"].apply(fmt_date)
        df_h.columns = [c.replace("_"," ").title() for c in df_h.columns]
        story.append(make_table(df_h, [page_w/len(df_h.columns)]*len(df_h.columns)))
        story.append(Spacer(1, 5*mm))

    if not df_expenses.empty:
        story.append(Paragraph("Vehicle Maintenance Expenses", section_style))
        exp_cols = [c for c in ["reg_number","category","description","cost"] if c in df_expenses.columns]
        df_e = df_expenses[exp_cols].copy()
        df_e.columns = [c.replace("_"," ").title() for c in df_e.columns]
        story.append(make_table(df_e, [page_w/len(df_e.columns)]*len(df_e.columns)))
        story.append(Spacer(1, 5*mm))

    if not df_admin_exp.empty:
        story.append(Paragraph("Administrative / Overhead Costs", section_style))
        adm_cols = [c for c in ["date","category","description","cost","logged_by"] if c in df_admin_exp.columns]
        df_a = df_admin_exp[adm_cols].copy()
        df_a["date"] = df_a["date"].apply(fmt_date)
        df_a.columns = [c.replace("_"," ").title() for c in df_a.columns]
        story.append(make_table(df_a, [page_w/len(df_a.columns)]*len(df_a.columns)))

    doc.build(story)
    return buffer.getvalue()


def generate_asset_fleet_pdf(df_report: pd.DataFrame, time_label: str) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=12*mm, rightMargin=12*mm, topMargin=18*mm, bottomMargin=18*mm)
    styles = getSampleStyleSheet()
    heading_style = ParagraphStyle("Heading2x", parent=styles["Heading1"], fontSize=15, textColor=colors.HexColor("#1a1a2e"), spaceAfter=4, alignment=TA_CENTER)
    sub_style     = ParagraphStyle("Sub2x", parent=styles["Normal"], fontSize=9, textColor=colors.grey, spaceAfter=2, alignment=TA_CENTER)
    cell_style    = ParagraphStyle("Cell2x", parent=styles["Normal"], fontSize=6.8, leading=9)
    hdr_style     = ParagraphStyle("Hdr2x", parent=styles["Normal"], fontSize=6.8, textColor=colors.white, alignment=TA_CENTER)
    HEADER_BG  = colors.HexColor("#16213e")
    FLEET_BG   = colors.HexColor("#dce6f0")
    ALT_ROW_BG = colors.HexColor("#f5f7fa")
    BORDER_CLR = colors.HexColor("#cccccc")

    story = [
        Paragraph("Fleet Manager Enterprise", heading_style),
        Paragraph("Asset & Fleet Performance Report", sub_style),
        Paragraph(f"Period: {time_label}  |  Generated: {datetime.now().strftime('%d-%m-%Y %H:%M')}", sub_style),
        Spacer(1, 6*mm),
    ]

    headers = [Paragraph(f"<b>{c}</b>", hdr_style) for c in df_report.columns]
    rows = [headers]
    fleet_row_index = None

    def strip_emoji(text):
        for ch in ("🔴","🟡","🟢"):
            text = text.replace(ch,"")
        return text.strip()

    for i, (_, row) in enumerate(df_report.iterrows()):
        if str(row["Vehicle"]) == "FLEET TOTAL":
            fleet_row_index = i + 1
        formatted = []
        for col, val in row.items():
            if "MWK" in col and isinstance(val,(int,float)):
                formatted.append(Paragraph(f"{val:,.0f}", cell_style))
            elif col == "Status":
                formatted.append(Paragraph(strip_emoji(str(val)), cell_style))
            else:
                formatted.append(Paragraph(str(val), cell_style))
        rows.append(formatted)

    page_w = A4[0] - 24*mm
    n_cols = len(df_report.columns)
    tbl = Table(rows, colWidths=[page_w/n_cols]*n_cols, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0,0), (-1,0), HEADER_BG),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTSIZE", (0,0), (-1,-1), 6.8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, ALT_ROW_BG]),
        ("GRID", (0,0), (-1,-1), 0.4, BORDER_CLR),
        ("TOPPADDING", (0,0), (-1,-1), 3),
        ("BOTTOMPADDING", (0,0), (-1,-1), 3),
        ("LEFTPADDING", (0,0), (-1,-1), 3),
        ("RIGHTPADDING", (0,0), (-1,-1), 3),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]
    if fleet_row_index is not None:
        style_cmds.append(("BACKGROUND", (0,fleet_row_index), (-1,fleet_row_index), FLEET_BG))
        style_cmds.append(("FONTNAME", (0,fleet_row_index), (-1,fleet_row_index), "Helvetica-Bold"))
    tbl.setStyle(TableStyle(style_cmds))
    story.append(tbl)
    doc.build(story)
    return buffer.getvalue()


def parse_date_gte(dt_str: str, cutoff) -> bool:
    try:
        return datetime.strptime(dt_str, "%Y-%m-%d").date() >= cutoff
    except Exception:
        return False

def fmt_date(dt_str: str) -> str:
    try:
        return datetime.strptime(dt_str, "%Y-%m-%d").strftime("%d-%m-%Y")
    except Exception:
        return dt_str or "—"


# =============================================================================
# WORKSPACE AUTHENTICATION GATEKEEPER
# =============================================================================

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None

def verify_login(username: str, password: str) -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, role, is_active FROM users WHERE username = %s", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        if row["is_active"] == 0:
            return "DEACTIVATED"
        if verify_password(password, row["password_hash"]):
            st.session_state.authenticated = True
            st.session_state.user = username
            st.session_state.role = row["role"]
            log_action(username, "Logged in.")
            return "SUCCESS"
    return "FAILED"

def trigger_logout():
    log_action(st.session_state.user, "Logged out.")
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.role = None
    st.rerun()

if not st.session_state.authenticated:
    st.title("🔐 Fleet Manager")
    with st.form("login_gate"):
        st.subheader("Sign In")
        input_user = st.text_input("Username:")
        input_pass = st.text_input("Password:", type="password")
        if st.form_submit_button("Sign In"):
            login_result = verify_login(input_user, input_pass)
            if login_result == "SUCCESS":
                st.success("Access granted.")
                st.rerun()
            elif login_result == "DEACTIVATED":
                st.error("This account has been deactivated. Please contact your administrator.")
            else:
                st.error("Invalid username or password.")
    st.stop()


# =============================================================================
# NAVIGATION PLATFORM LAYOUT
# =============================================================================

st.sidebar.title("🏁 Fleet Manager")
st.sidebar.markdown(f"**User:** `{st.session_state.user}`")
st.sidebar.markdown(f"**Role:** `{st.session_state.role}`")

if st.sidebar.button("🚪 Log Out"):
    trigger_logout()

navigation_routes = ["📊 Reports", "📝 New Rental", "🔧 Maintenance"]
if st.session_state.role == "Admin":
    navigation_routes.append("🚘 Fleet Registry")
    navigation_routes.append("🛡️ Admin Panel")

menu = st.sidebar.radio("Navigate:", navigation_routes, key="main_nav")

st.sidebar.markdown("---")
st.sidebar.caption("v1.4.2 • Developed by chiMs")
st.sidebar.caption("© 2026 Fleet Manager Enterprise")

# =============================================================================
# SECTION 1: REPORTS DASHBOARD
# =============================================================================
if menu == "📊 Reports":
    conn = get_db_connection()
    st.title("📊 Fleet Control Room & Reporting Engine")

    df_vehicles_raw  = pd.read_sql_query("SELECT reg_number, model, vehicle_type FROM vehicles", conn)
    df_hires_raw     = pd.read_sql_query("SELECT * FROM hires", conn)
    df_expenses_raw  = pd.read_sql_query("SELECT * FROM expenses", conn)
    df_admin_exp_raw = pd.read_sql_query("SELECT * FROM admin_expenses", conn)

    is_admin = st.session_state.role == "Admin"

    unique_types   = ["All Classifications"] + sorted(df_vehicles_raw["vehicle_type"].unique().tolist()) if not df_vehicles_raw.empty else ["All Classifications"]
    vehicle_plates = sorted(df_vehicles_raw["reg_number"].unique().tolist()) if not df_vehicles_raw.empty else []
    unique_assets  = (["Entire Fleet"] + vehicle_plates) if is_admin else vehicle_plates
    category_options = sorted(df_vehicles_raw["vehicle_type"].dropna().unique().tolist()) if not df_vehicles_raw.empty else []

    st.markdown("### 🛠️ Report Filters")
    fc1, fc2, fc3 = st.columns(3)

    if is_admin:
        selected_class = fc1.selectbox("Asset Type:", unique_types)
        selected_asset = fc2.selectbox("Asset:", unique_assets)
    else:
        selected_asset = "Entire Fleet"
        if category_options:
            selected_class = fc1.selectbox("Asset Classification Category:", category_options)
        else:
            st.warning("No asset categories registered yet.")
            st.stop()

    time_col = fc3 if is_admin else fc2
    time_scope = time_col.selectbox("Time Window:", ["Daily (Today)", "Weekly (Last 7 Days)", "Monthly (Last 30 Days)", "Yearly (Current Year)", "All Time"])

    today_dt = datetime.now().date()
    start_filter_date = None
    if time_scope == "Daily (Today)":
        start_filter_date = today_dt
    elif time_scope == "Weekly (Last 7 Days)":
        start_filter_date = today_dt - timedelta(days=7)
    elif time_scope == "Monthly (Last 30 Days)":
        start_filter_date = today_dt - timedelta(days=30)
    elif time_scope == "Yearly (Current Year)":
        start_filter_date = datetime(today_dt.year, 1, 1).date()

    if not df_hires_raw.empty and not df_vehicles_raw.empty:
        df_merged_hires = df_hires_raw.merge(df_vehicles_raw, on="reg_number", how="left")
    else:
        df_merged_hires = df_hires_raw.copy()
        df_merged_hires["vehicle_type"] = "Unknown"
        df_merged_hires["model"] = "Unknown"

    if not df_expenses_raw.empty and not df_vehicles_raw.empty:
        df_merged_expenses = df_expenses_raw.merge(df_vehicles_raw, on="reg_number", how="left")
    else:
        df_merged_expenses = df_expenses_raw.copy()
        df_merged_expenses["vehicle_type"] = "Unknown"
        df_merged_expenses["model"] = "Unknown"

    if selected_class != "All Classifications":
        df_merged_hires = df_merged_hires[df_merged_hires["vehicle_type"] == selected_class]
        df_merged_expenses = df_merged_expenses[df_merged_expenses["vehicle_type"] == selected_class]

    if selected_asset != "Entire Fleet":
        df_merged_hires = df_merged_hires[df_merged_hires["reg_number"] == selected_asset]
        df_merged_expenses = df_merged_expenses[df_merged_expenses["reg_number"] == selected_asset]

    if start_filter_date is not None and not df_merged_hires.empty:
        df_merged_hires = df_merged_hires[df_merged_hires["date_out"].apply(lambda d: parse_date_gte(d, start_filter_date))]

    if not is_admin:
        st.info(f"📌 Showing data for the **{selected_class}** category only. Contact an Admin for fleet-wide or per-vehicle reports.")

    st.markdown("#### 💾 Export Filtered Datasets")

    clean_class_name = selected_class.replace(" ","_").lower()
    clean_asset_name = selected_asset.replace(" ","_").lower()
    clean_time_name  = time_scope.split(" ")[0].lower()
    file_stub = f"{clean_class_name}_{clean_asset_name}_{clean_time_name}"

    df_admin_for_export = df_admin_exp_raw.copy() if is_admin else pd.DataFrame()
    if is_admin and start_filter_date is not None and not df_admin_for_export.empty:
        df_admin_for_export = df_admin_for_export[df_admin_for_export["date"].apply(lambda d: parse_date_gte(d, start_filter_date))]

    export_format = st.radio("Choose export format:", ["📄 CSV (raw data)", "📕 PDF (formatted report)"], horizontal=True)

    if export_format == "📄 CSV (raw data)":
        dl_col1, dl_col2 = st.columns(2)
        if not df_merged_hires.empty:
            df_downloadable_hires = df_merged_hires.drop(columns=["national_id_image"], errors="ignore")
            dl_col1.download_button(label=f"📥 Download Hires Ledger ({len(df_downloadable_hires)} rows)", data=convert_df_to_csv(df_downloadable_hires), file_name=f"hires_report_{file_stub}.csv", mime="text/csv", key="dl_btn_hires_csv")
        else:
            dl_col1.info("No rental invoice matches found.")
        if not df_merged_expenses.empty:
            dl_col2.download_button(label=f"📥 Download Workshop Expenses ({len(df_merged_expenses)} rows)", data=convert_df_to_csv(df_merged_expenses), file_name=f"expenses_report_{file_stub}.csv", mime="text/csv", key="dl_btn_exp_csv")
        else:
            dl_col2.info("No workshop expense logs match.")
        if is_admin:
            if not df_admin_for_export.empty:
                st.download_button(label=f"📥 Download Admin Costs ({len(df_admin_for_export)} rows)", data=convert_df_to_csv(df_admin_for_export), file_name=f"admin_costs_report_{file_stub}.csv", mime="text/csv", key="dl_btn_admin_csv")
            else:
                st.caption("No admin cost entries match this time window.")
    else:
        if df_merged_hires.empty and df_merged_expenses.empty and df_admin_for_export.empty:
            st.info("No data matches these filter bounds.")
        else:
            if selected_asset != "Entire Fleet":
                scope_label = f"{selected_asset}" + (f" — {selected_class}" if selected_class != "All Classifications" else "")
            elif selected_class != "All Classifications":
                scope_label = f"{selected_class} (all vehicles in category)"
            else:
                scope_label = "Entire Fleet"
            pdf_bytes = generate_pdf_report(
                title="Financial & Operations Report", subtitle=scope_label,
                df_hires=df_merged_hires.drop(columns=["national_id_image"], errors="ignore"),
                df_expenses=df_merged_expenses, df_admin_exp=df_admin_for_export,
                scope_label=scope_label, time_label=time_scope,
            )
            st.download_button(label="📥 Download PDF Report", data=pdf_bytes, file_name=f"fleet_report_{file_stub}.pdf", mime="application/pdf", key="dl_btn_pdf")

    st.markdown("---")
    st.markdown("### 🚨 Live Yard Monitor & Alerts Board")

    df_active_hires = df_merged_hires[df_merged_hires["is_active"] == 1] if not df_merged_hires.empty else pd.DataFrame()
    overdue_list = []
    due_today_list = []
    active_on_track = []

    if not df_active_hires.empty:
        for _, hire_row in df_active_hires.iterrows():
            try:
                expected_return_date = datetime.strptime(hire_row['date_returned'], "%Y-%m-%d").date()
            except ValueError:
                expected_return_date = today_dt
            if expected_return_date < today_dt:
                overdue_list.append(hire_row)
            elif expected_return_date == today_dt:
                due_today_list.append(hire_row)
            else:
                active_on_track.append(hire_row)

    m_col1, m_col2, m_col3 = st.columns(3)
    m_col1.metric("🔴 Critical Overdue Assets", f"{len(overdue_list)} unit(s)")
    m_col2.metric("🟡 Returns Expected Today", f"{len(due_today_list)} unit(s)")
    m_col3.metric("🟢 Active On-Road Rentals", f"{len(active_on_track)} unit(s)")

    with st.expander("🔍 View Action Sheets", expanded=len(overdue_list)>0 or len(due_today_list)>0):
        tab_overdue, tab_today, tab_on_road = st.tabs([f"🔴 Overdue ({len(overdue_list)})", f"🟡 Due Today ({len(due_today_list)})", f"🟢 On Road ({len(active_on_track)})"])
        with tab_overdue:
            if overdue_list:
                for ov in overdue_list:
                    days_late = (today_dt - datetime.strptime(ov['date_returned'], "%Y-%m-%d").date()).days
                    st.error(f"⚠️ **Contract {ov['hire_id']}** is **{days_late} day(s) LATE** | Asset: `{ov['reg_number']}` | Client: **{ov['customer_name']}** ({ov['customer_phone']}) | Balance: **{ov['balance']:,.0f} MWK**")
            else:
                st.success("No overdue assets.")
        with tab_today:
            if due_today_list:
                for td in due_today_list:
                    st.warning(f"🕒 **Contract {td['hire_id']}** due today | Asset: `{td['reg_number']}` | Client: **{td['customer_name']}**")
            else:
                st.info("No returns today.")
        with tab_on_road:
            if active_on_track:
                for or_item in active_on_track:
                    st.info(f"🚘 **{or_item['hire_id']}** | Asset: `{or_item['reg_number']}` | Due: `{fmt_date(or_item['date_returned'])}` | Client: **{or_item['customer_name']}**")
            else:
                st.caption("No assets currently on road.")

    st.markdown("---")

    if is_admin:
        st.markdown("### 📑 Asset & Fleet Performance Report")
        report_rows = []
        for _, veh in df_vehicles_raw.iterrows():
            reg = veh["reg_number"]
            veh_hires = df_hires_raw[df_hires_raw["reg_number"] == reg].copy() if not df_hires_raw.empty else pd.DataFrame()
            if start_filter_date is not None and not veh_hires.empty:
                veh_hires = veh_hires[veh_hires["date_out"].apply(lambda d: parse_date_gte(d, start_filter_date))]
            gross_rev   = veh_hires["amount_due"].sum()  if not veh_hires.empty else 0
            collected   = veh_hires["amount_paid"].sum() if not veh_hires.empty else 0
            outstanding = veh_hires["balance"].sum()     if not veh_hires.empty else 0
            veh_maint   = df_expenses_raw[df_expenses_raw["reg_number"] == reg]["cost"].sum() if not df_expenses_raw.empty else 0
            profit = gross_rev - veh_maint
            status_label = "No Active Rental"
            due_date_display = "—"
            if not df_hires_raw.empty:
                active_match = df_hires_raw[(df_hires_raw["reg_number"] == reg) & (df_hires_raw["is_active"] == 1)]
                if not active_match.empty:
                    a_row = active_match.iloc[0]
                    try:
                        exp_ret = datetime.strptime(a_row["date_returned"], "%Y-%m-%d").date()
                    except Exception:
                        exp_ret = today_dt
                    due_date_display = fmt_date(a_row["date_returned"])
                    if exp_ret < today_dt:
                        status_label = f"🔴 Overdue ({(today_dt - exp_ret).days}d late)"
                    elif exp_ret == today_dt:
                        status_label = "🟡 Due Today"
                    else:
                        status_label = "🟢 Due in Future"
            report_rows.append({"Vehicle": reg, "Model": veh.get("model","—"), "Gross Revenue (MWK)": gross_rev, "Total Collected (MWK)": collected, "Outstanding (MWK)": outstanding, "Maintenance Costs (MWK)": veh_maint, "Profit (MWK)": profit, "Status": status_label, "Due Date": due_date_display})

        df_asset_report = pd.DataFrame(report_rows)
        if not df_asset_report.empty:
            n_overdue    = sum(1 for r in report_rows if r["Status"].startswith("🔴"))
            n_due_today  = sum(1 for r in report_rows if r["Status"].startswith("🟡"))
            n_due_future = sum(1 for r in report_rows if r["Status"].startswith("🟢"))
            df_admin_for_fleet_row = df_admin_exp_raw.copy()
            if start_filter_date is not None and not df_admin_for_fleet_row.empty:
                df_admin_for_fleet_row = df_admin_for_fleet_row[df_admin_for_fleet_row["date"].apply(lambda d: parse_date_gte(d, start_filter_date))]
            fleet_admin_cost = df_admin_for_fleet_row["cost"].sum() if not df_admin_for_fleet_row.empty else 0
            fleet_profit_net = df_asset_report["Profit (MWK)"].sum() - fleet_admin_cost
            fleet_row = {"Vehicle": "FLEET TOTAL", "Model": f"{len(df_asset_report)} vehicle(s)", "Gross Revenue (MWK)": df_asset_report["Gross Revenue (MWK)"].sum(), "Total Collected (MWK)": df_asset_report["Total Collected (MWK)"].sum(), "Outstanding (MWK)": df_asset_report["Outstanding (MWK)"].sum(), "Maintenance Costs (MWK)": df_asset_report["Maintenance Costs (MWK)"].sum(), "Profit (MWK)": fleet_profit_net, "Status": f"🔴 {n_overdue} overdue | 🟡 {n_due_today} today | 🟢 {n_due_future} future", "Due Date": "(see vehicle rows)"}
            df_asset_report_display = pd.concat([df_asset_report, pd.DataFrame([fleet_row])], ignore_index=True)
            st.dataframe(df_asset_report_display, use_container_width=True, column_config={"Gross Revenue (MWK)": st.column_config.NumberColumn(format="%d"), "Total Collected (MWK)": st.column_config.NumberColumn(format="%d"), "Outstanding (MWK)": st.column_config.NumberColumn(format="%d"), "Maintenance Costs (MWK)": st.column_config.NumberColumn(format="%d"), "Profit (MWK)": st.column_config.NumberColumn(format="%d")})
            rep_col1, rep_col2 = st.columns(2)
            rep_col1.download_button(label="📥 Download Report as CSV", data=convert_df_to_csv(df_asset_report_display), file_name=f"asset_fleet_performance_{file_stub}.csv", mime="text/csv", key="dl_btn_asset_report_csv")
            rep_col2.download_button(label="📥 Download Report as PDF", data=generate_asset_fleet_pdf(df_asset_report_display, time_scope), file_name=f"asset_fleet_performance_{file_stub}.pdf", mime="application/pdf", key="dl_btn_asset_report_pdf")
        else:
            st.info("No vehicles registered yet.")

    st.markdown("---")

    if is_admin:
        tab_overview, tab_profitability = st.tabs(["📈 Fleet Balances", "💰 Asset Profitability"])
    else:
        tab_overview, = st.tabs([f"📈 {selected_class} — Financial Summary"])

    with tab_overview:
        st.subheader("Financial Performance (Scoped)")
        total_sales   = df_merged_hires["amount_due"].sum()  if not df_merged_hires.empty    else 0
        total_paid    = df_merged_hires["amount_paid"].sum() if not df_merged_hires.empty    else 0
        total_balance = df_merged_hires["balance"].sum()     if not df_merged_hires.empty    else 0
        total_veh_exp = df_merged_expenses["cost"].sum()     if not df_merged_expenses.empty else 0
        df_admin_filtered = df_admin_exp_raw.copy()
        if start_filter_date is not None and not df_admin_filtered.empty:
            df_admin_filtered = df_admin_filtered[df_admin_filtered["date"].apply(lambda d: parse_date_gte(d, start_filter_date))]
        total_admin_exp = df_admin_filtered["cost"].sum() if not df_admin_filtered.empty else 0
        total_all_exp = total_veh_exp + (total_admin_exp if is_admin else 0)

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Gross Revenue (Due)", f"{total_sales:,.0f} MWK")
        c2.metric("Total Collected", f"{total_paid:,.0f} MWK", delta=f"{total_balance:,.0f} outstanding", delta_color="inverse")
        c3.metric("Vehicle Expenses", f"{total_veh_exp:,.0f} MWK", delta_color="inverse")
        if is_admin:
            c4.metric("Admin Overheads", f"{total_admin_exp:,.0f} MWK", delta_color="inverse")
            c5.metric("Net Margin", f"{total_sales - total_all_exp:,.0f} MWK")
        else:
            c4.metric("Net Margin (Vehicle)", f"{total_sales - total_veh_exp:,.0f} MWK")

        if is_admin:
            st.markdown("---")
            st.subheader("⛽ Cash Runway")
            this_month_str = datetime.now().date().replace(day=1).strftime("%Y-%m")
            if not df_hires_raw.empty:
                df_hires_raw["_month"] = df_hires_raw["date_out"].str[:7]
                cash_this_month = df_hires_raw[df_hires_raw["_month"] == this_month_str]["amount_paid"].sum()
            else:
                cash_this_month = 0.0
            if not df_expenses_raw.empty and "date" in df_expenses_raw.columns:
                df_expenses_raw["_month"] = df_expenses_raw["date"].str[:7]
                avg_monthly_veh = df_expenses_raw.groupby("_month")["cost"].sum().mean()
            elif not df_expenses_raw.empty:
                months_active = max(len(df_hires_raw["date_out"].str[:7].unique()) if not df_hires_raw.empty else 1, 1)
                avg_monthly_veh = df_expenses_raw["cost"].sum() / months_active
            else:
                avg_monthly_veh = 0.0
            if not df_admin_exp_raw.empty:
                df_admin_exp_raw["_month"] = df_admin_exp_raw["date"].str[:7]
                avg_monthly_admin = df_admin_exp_raw.groupby("_month")["cost"].sum().mean()
            else:
                avg_monthly_admin = 0.0
            avg_total_monthly_burn = avg_monthly_veh + avg_monthly_admin
            if avg_total_monthly_burn > 0:
                runway_months = cash_this_month / avg_total_monthly_burn
                runway_colour = "normal" if runway_months >= 3 else ("off" if runway_months >= 1 else "inverse")
            else:
                runway_months = None
                runway_colour = "off"
            rw1, rw2, rw3, rw4 = st.columns(4)
            rw1.metric("Cash Collected (This Month)", f"{cash_this_month:,.0f} MWK")
            rw2.metric("Avg Monthly Vehicle Costs", f"{avg_monthly_veh:,.0f} MWK")
            rw3.metric("Avg Monthly Admin Costs", f"{avg_monthly_admin:,.0f} MWK")
            if runway_months is not None:
                rw4.metric("⛽ Runway", f"{runway_months:.1f} months", delta="Healthy" if runway_months >= 3 else ("Watch" if runway_months >= 1 else "Critical"), delta_color=runway_colour)
            else:
                rw4.metric("⛽ Runway", "N/A", delta="No cost data yet", delta_color="off")

        if is_admin and not df_admin_filtered.empty:
            st.markdown("---")
            st.subheader("🏢 Admin Cost Breakdown")
            admin_by_cat = df_admin_filtered.groupby("category")["cost"].sum().reset_index().rename(columns={"category":"Category","cost":"Total (MWK)"}).sort_values("Total (MWK)", ascending=False)
            st.dataframe(admin_by_cat, use_container_width=True, column_config={"Total (MWK)": st.column_config.NumberColumn(format="%d MWK")})

    if is_admin:
        with tab_profitability:
            st.subheader("Asset Net Performance (Filtered Scope)")
            if total_admin_exp > 0:
                st.info(f"ℹ️ Admin overheads for this period total **MWK {total_admin_exp:,.0f}**")
            if df_vehicles_raw.empty:
                st.info("Add assets to view profitability.")
            else:
                visible_plates = df_merged_hires["reg_number"].unique().tolist() if not df_merged_hires.empty else []
                if selected_asset != "Entire Fleet":
                    visible_plates = [selected_asset]
                df_scoped_vehicles = df_vehicles_raw[df_vehicles_raw["reg_number"].isin(visible_plates)] if visible_plates else df_vehicles_raw
                if selected_class != "All Classifications":
                    df_scoped_vehicles = df_scoped_vehicles[df_scoped_vehicles["vehicle_type"] == selected_class]
                profit_data_rows = []
                for _, v_row in df_scoped_vehicles.iterrows():
                    plate = v_row['reg_number']
                    sub_hires = df_merged_hires[df_merged_hires["reg_number"] == plate] if not df_merged_hires.empty else pd.DataFrame()
                    sub_exp   = df_merged_expenses[df_merged_expenses["reg_number"] == plate] if not df_merged_expenses.empty else pd.DataFrame()
                    unit_revenue  = sub_hires["amount_paid"].sum() if not sub_hires.empty else 0.0
                    unit_expenses = sub_exp["cost"].sum() if not sub_exp.empty else 0.0
                    profit_data_rows.append({"Asset Code/Plate": plate, "Type": v_row['vehicle_type'], "Model / Description": v_row['model'], "Total Revenue Collected (MWK)": unit_revenue, "Maintenance Overhead (MWK)": unit_expenses, "Net Performance Margin (MWK)": unit_revenue - unit_expenses})
                if profit_data_rows:
                    df_pnl = pd.DataFrame(profit_data_rows)
                    st.dataframe(df_pnl.sort_values(by="Net Performance Margin (MWK)", ascending=False), use_container_width=True, column_config={"Total Revenue Collected (MWK)": st.column_config.NumberColumn(format="%d MWK"), "Maintenance Overhead (MWK)": st.column_config.NumberColumn(format="%d MWK"), "Net Performance Margin (MWK)": st.column_config.NumberColumn(format="%d MWK")})
                else:
                    st.caption("No financial data within these parameters.")

    st.markdown("---")
    st.subheader("📋 Comprehensive Invoice Ledgers (Scoped View)")

    if not df_merged_hires.empty:
        for _, row in df_merged_hires.iterrows():
            status_badge = "🟢 Active" if row['is_active'] == 1 else "🏁 Returned & Settled"
            with st.expander(f"📄 [{status_badge}] {row['hire_id']} — {row['customer_name']} ({row['reg_number']})"):
                col_id1, col_id2 = st.columns([1,2])
                with col_id1:
                    st.markdown(f"**Classification:** `{row.get('vehicle_type','Standard Car')}`")
                    st.markdown(f"**National ID:** `{row['national_id_number'] or 'Not recorded'}`")
                    st.markdown(f"**Duration:** `{row['days']} day(s)`")
                    st.markdown(f"**Expected Return:** `{fmt_date(row['date_returned'])}`")
                with col_id2:
                    if "national_id_image" in row and row["national_id_image"]:
                        st.image(bytes(row["national_id_image"]), caption=f"ID — {row['customer_name']}", width=250)
                    else:
                        st.caption("No ID image on file.")

                with st.form(f"edit_hire_{row['hire_id']}"):
                    col1, col2 = st.columns(2)
                    edit_paid   = col1.number_input("Amount Paid (MWK):", value=float(row["amount_paid"]), step=5000.0, key=f"p_{row['hire_id']}")
                    edit_rate   = col2.number_input("Daily Rate (MWK):", value=float(row["rate_per_day"]), step=1000.0, key=f"r_{row['hire_id']}")
                    edit_method = col1.selectbox("Payment Method:", ["Cash","Airtel Money","Bank Transfer"], index=["Cash","Airtel Money","Bank Transfer"].index(row["payment_method"]), key=f"m_{row['hire_id']}")
                    col_b1, col_b2, col_b3 = st.columns([1,1,2])
                    save_changes   = col_b1.form_submit_button("💾 Save")
                    process_return = col_b2.form_submit_button("🏁 Return Asset") if row['is_active'] == 1 else False
                    delete_record  = col_b3.form_submit_button("🗑️ Drop Invoice") if st.session_state.role == "Admin" else False

                    if save_changes:
                        new_due     = int(row["days"]) * edit_rate
                        new_balance = new_due - edit_paid
                        write_conn = get_db_connection()
                        cursor = write_conn.cursor()
                        cursor.execute('UPDATE hires SET amount_paid=%s, rate_per_day=%s, amount_due=%s, balance=%s, payment_method=%s WHERE hire_id=%s', (edit_paid, edit_rate, new_due, new_balance, edit_method, row["hire_id"]))
                        write_conn.commit()
                        write_conn.close()
                        log_action(st.session_state.user, f"Updated record: {row['hire_id']}.")
                        st.success("Record updated.")
                        st.rerun()

                    if process_return:
                        write_conn = get_db_connection()
                        cursor = write_conn.cursor()
                        cursor.execute("UPDATE hires SET is_active = 0 WHERE hire_id = %s", (row["hire_id"],))
                        cursor.execute("UPDATE vehicles SET status = 'Available' WHERE reg_number = %s", (row["reg_number"],))
                        write_conn.commit()
                        write_conn.close()
                        log_action(st.session_state.user, f"Processed return: {row['hire_id']}.")
                        st.success(f"Asset {row['reg_number']} returned to yard.")
                        st.rerun()

                    if delete_record:
                        write_conn = get_db_connection()
                        cursor = write_conn.cursor()
                        if row['is_active'] == 1:
                            cursor.execute("UPDATE vehicles SET status = 'Available' WHERE reg_number = %s", (row["reg_number"],))
                        cursor.execute("DELETE FROM hires WHERE hire_id = %s", (row["hire_id"],))
                        write_conn.commit()
                        write_conn.close()
                        log_action(st.session_state.user, f"Deleted hire: {row['hire_id']}.")
                        st.warning(f"Record {row['hire_id']} dropped.")
                        st.rerun()
    else:
        st.info("No records match the current filters.")

    conn.close()
    st.stop()


# =============================================================================
# SECTION 2: NEW RENTAL
# =============================================================================
elif menu == "📝 New Rental":
    conn = get_db_connection()
    st.title("📝 New Walk-In Booking Desk")

    is_admin_nr = st.session_state.role == "Admin"
    db_vehicles_all = pd.read_sql_query("SELECT reg_number, model, vehicle_type FROM vehicles WHERE status = 'Available'", conn)

    if is_admin_nr:
        db_vehicles = db_vehicles_all
    else:
        category_opts_nr = sorted(db_vehicles_all["vehicle_type"].dropna().unique().tolist())
        if not category_opts_nr:
            db_vehicles = db_vehicles_all
        else:
            picked_category_nr = st.selectbox("Asset Classification Category:", category_opts_nr)
            st.caption(f"📌 Showing only **{picked_category_nr}** vehicles.")
            db_vehicles = db_vehicles_all[db_vehicles_all["vehicle_type"] == picked_category_nr]

    if db_vehicles.empty:
        st.warning("⚠️ No fleet assets currently 'Available'.")
    else:
        vehicle_list = [f"{r['reg_number']} — {r['model']} ({r['vehicle_type']})" for _, r in db_vehicles.iterrows()]

        with st.form("new_walk_in_entry"):
            st.subheader("Client & Deployment Details")
            col1, col2 = st.columns(2)
            walkin_name        = col1.text_input("Client/Company Full Name:")
            walkin_phone       = col1.text_input("Contact Phone Number:")
            chosen_vehicle_raw = col1.selectbox("Select Available Asset:", vehicle_list)
            loc                = col1.text_input("Dispatch Deployment Location:", value="Blantyre")
            h_id           = col2.text_input("Contract ID:", value=generate_hire_id())
            rate           = col2.number_input("Daily Hire Rate (MWK):", value=80000, step=5000)
            d_out          = col2.date_input("Deployment Date Out:", datetime.now().date(), format="DD/MM/YYYY")
            duration_days  = col2.number_input("Duration Horizon (days):", min_value=1, value=1, step=1)

            st.markdown("---")
            st.subheader("🪪 Authorization / Customer ID")
            col_id_num, col_id_file = st.columns(2)
            id_number = col_id_num.text_input("National ID or Business Reg Number:")
            id_file   = col_id_file.file_uploader("Upload ID Document/Permit Image:", type=["png","jpg","jpeg"])

            st.markdown("---")
            col3, col4 = st.columns(2)
            paid    = col3.number_input("Initial Payment Deposit (MWK):", value=100000, step=10000)
            routing = col4.selectbox("Payment Mode Routing:", ["Cash","Airtel Money","Bank Transfer"])

            if st.form_submit_button("⚡ Save Deployment Contract"):
                if not walkin_name.strip():
                    st.error("Client name is required.")
                elif not h_id.strip():
                    st.error("Contract ID is required.")
                else:
                    selected_reg    = chosen_vehicle_raw.split(" — ")[0]
                    computed_return = d_out + timedelta(days=int(duration_days))
                    due             = int(duration_days) * rate
                    bal             = due - paid
                    binary_image    = id_file.read() if id_file is not None else None

                    check_conn = get_db_connection()
                    cursor = check_conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM hires WHERE hire_id = %s", (h_id,))
                    exists = cursor.fetchone()["count"]
                    check_conn.close()

                    if exists > 0:
                        st.warning(f"Contract ID {h_id} already exists.")
                    else:
                        try:
                            write_conn = get_db_connection()
                            cursor = write_conn.cursor()
                            cursor.execute("SELECT id FROM customers WHERE phone = %s", (walkin_phone.strip(),))
                            existing = cursor.fetchone()
                            if not existing:
                                cursor.execute("INSERT INTO customers (name, phone) VALUES (%s, %s)", (walkin_name.strip(), walkin_phone.strip()))
                            cursor.execute("UPDATE vehicles SET status = 'Rented' WHERE reg_number = %s", (selected_reg,))
                            cursor.execute(
                                '''INSERT INTO hires (hire_id, reg_number, customer_name, customer_phone,
                                   national_id_number, national_id_image, date_out, date_returned,
                                   location, rate_per_day, days, amount_due, amount_paid, balance,
                                   payment_method, received_by, is_active)
                                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1)''',
                                (h_id, selected_reg, walkin_name.strip(), walkin_phone.strip(), id_number.strip(), binary_image,
                                 str(d_out), str(computed_return), loc.strip(), rate, int(duration_days),
                                 due, paid, bal, routing, st.session_state.user)
                            )
                            write_conn.commit()
                            write_conn.close()
                            log_action(st.session_state.user, f"Created dispatch file {h_id}. Asset {selected_reg} marked Rented.")
                            st.success(f"Contract logged. Expected return: **{computed_return.strftime('%d-%m-%Y')}**")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Database error: {e}")

    conn.close()
    st.stop()


# =============================================================================
# SECTION 3: MAINTENANCE LOGGING
# =============================================================================
elif menu == "🔧 Maintenance":
    conn = get_db_connection()
    st.title("🔧 Costs & Maintenance")

    is_admin_maint = st.session_state.role == "Admin"

    if "maint_success_msg" in st.session_state:
        st.success(st.session_state.maint_success_msg)
        del st.session_state.maint_success_msg
    if "admin_success_msg" in st.session_state:
        st.success(st.session_state.admin_success_msg)
        del st.session_state.admin_success_msg

    if is_admin_maint:
        tab_vehicle, tab_admin = st.tabs(["🚗 Vehicle Costs", "🏢 Admin Costs"])
    else:
        tab_vehicle, = st.tabs(["🚗 Vehicle Costs"])

    with tab_vehicle:
        st.subheader("Log Vehicle Maintenance Expense")
        db_vehicles_all = pd.read_sql_query("SELECT reg_number, model, vehicle_type, status FROM vehicles", conn)

        if is_admin_maint:
            db_vehicles = db_vehicles_all
        else:
            category_opts_maint = sorted(db_vehicles_all["vehicle_type"].dropna().unique().tolist())
            if not category_opts_maint:
                db_vehicles = db_vehicles_all
            else:
                picked_category_maint = st.selectbox("Asset Classification Category:", category_opts_maint)
                st.caption(f"📌 Showing only **{picked_category_maint}** vehicles.")
                db_vehicles = db_vehicles_all[db_vehicles_all["vehicle_type"] == picked_category_maint]

        if db_vehicles.empty:
            st.error("No fleet assets registered.")
        else:
            veh_options = {row['reg_number']: f"[{row['vehicle_type']}] {row['reg_number']} — {row['model']} ({row['status']})" for _, row in db_vehicles.iterrows()}
            target_plate = st.selectbox("Select Vehicle:", list(veh_options.keys()), format_func=lambda x: veh_options[x])

            with st.form("new_maintenance_expense"):
                cat    = st.selectbox("Category:", ["Gearbox","Engine","Body Works","Painting","Tyres","Fuel","Other"])
                desc   = st.text_input("Description:")
                charge = st.number_input("Cost (MWK):", min_value=0, value=45000)
                ground_car = st.checkbox("Mark vehicle as 'In Shop'", value=False)

                if st.form_submit_button("Save Vehicle Expense"):
                    if not desc.strip():
                        st.warning("Please enter a description.")
                    else:
                        read_conn = get_db_connection()
                        cursor = read_conn.cursor()
                        cursor.execute("SELECT status FROM vehicles WHERE reg_number = %s", (target_plate,))
                        current_status = cursor.fetchone()['status']
                        read_conn.close()

                        if ground_car and current_status == 'Rented':
                            st.error("Cannot mark as 'In Shop' — vehicle is on active rental.")
                        else:
                            write_conn = get_db_connection()
                            cursor = write_conn.cursor()
                            cursor.execute("INSERT INTO expenses (reg_number, category, description, cost) VALUES (%s, %s, %s, %s)", (target_plate, cat, desc.strip(), charge))
                            if ground_car:
                                cursor.execute("UPDATE vehicles SET status = 'In Shop' WHERE reg_number = %s", (target_plate,))
                                log_action(st.session_state.user, f"Marked {target_plate} as 'In Shop'.")
                            write_conn.commit()
                            write_conn.close()
                            log_action(st.session_state.user, f"Logged '{cat}' expense on {target_plate}: MWK {charge:,.0f}.")
                            st.session_state.maint_success_msg = f"🎉 Maintenance entry of **MWK {charge:,.0f}** for **[{target_plate}]** recorded."
                            st.rerun()

            st.markdown("---")
            st.subheader("🛠️ Vehicles Currently In Shop")
            shop_cars = db_vehicles[db_vehicles['status'] == 'In Shop']
            if not shop_cars.empty:
                for _, s_car in shop_cars.iterrows():
                    col_c1, col_c2 = st.columns([3,1])
                    col_c1.write(f"⚙️ **[{s_car['vehicle_type']}] {s_car['reg_number']}** ({s_car['model']})")
                    if col_c2.button(f"⚡ Release {s_car['reg_number']}", key=f"rel_{s_car['reg_number']}"):
                        write_conn = get_db_connection()
                        cursor = write_conn.cursor()
                        cursor.execute("UPDATE vehicles SET status = 'Available' WHERE reg_number = %s", (s_car['reg_number'],))
                        write_conn.commit()
                        write_conn.close()
                        log_action(st.session_state.user, f"Released {s_car['reg_number']} from shop.")
                        st.success(f"{s_car['reg_number']} is now available.")
                        st.rerun()
            else:
                st.caption("No vehicles in the workshop.")

    if is_admin_maint:
        with tab_admin:
            st.subheader("Log Administrative / Overhead Cost")
            st.caption("Costs not related to a specific vehicle — salaries, office rent, utilities, etc.")

            with st.form("new_admin_expense"):
                col_a1, col_a2 = st.columns(2)
                admin_cat  = col_a1.selectbox("Category:", ["Salaries & Wages","Office Rent","Utilities","Insurance","Stationery & Supplies","Marketing & Advertising","Professional Fees","Government Levies & Taxes","Other Admin Cost"])
                admin_date = col_a2.date_input("Date of Cost:", datetime.now().date(), format="DD/MM/YYYY")
                admin_desc = st.text_input("Description:")
                admin_cost = st.number_input("Amount (MWK):", min_value=0, value=0, step=5000)

                if st.form_submit_button("Save Admin Cost"):
                    if not admin_desc.strip():
                        st.warning("Please enter a description.")
                    elif admin_cost <= 0:
                        st.warning("Amount must be greater than zero.")
                    else:
                        write_conn = get_db_connection()
                        cursor = write_conn.cursor()
                        cursor.execute("INSERT INTO admin_expenses (date, category, description, cost, logged_by) VALUES (%s, %s, %s, %s, %s)", (str(admin_date), admin_cat, admin_desc.strip(), admin_cost, st.session_state.user))
                        write_conn.commit()
                        write_conn.close()
                        log_action(st.session_state.user, f"Logged admin cost '{admin_cat}': MWK {admin_cost:,.0f}.")
                        st.session_state.admin_success_msg = f"💼 Administrative expense **{admin_cat}** — **MWK {admin_cost:,.0f}** committed."
                        st.rerun()

            st.markdown("---")
            st.subheader("📋 Admin Cost Ledger")
            df_admin_exp = pd.read_sql_query("SELECT id, date, category, description, cost, logged_by FROM admin_expenses ORDER BY date DESC, id DESC", conn)

            if df_admin_exp.empty:
                st.info("No admin costs logged yet.")
            else:
                st.metric("Total Admin Costs on Record", f"{df_admin_exp['cost'].sum():,.0f} MWK")
                df_admin_display = df_admin_exp.copy()
                df_admin_display["date"] = df_admin_display["date"].apply(fmt_date)
                st.dataframe(df_admin_display.rename(columns={"id":"ID","date":"Date","category":"Category","description":"Description","cost":"Cost (MWK)","logged_by":"Logged By"}), use_container_width=True, column_config={"Cost (MWK)": st.column_config.NumberColumn(format="%d MWK")})

                st.markdown("---")
                st.subheader("🗑️ Delete Admin Cost Entry")
                entry_labels = {row["id"]: f"#{row['id']} — {fmt_date(row['date'])} | {row['category']} | MWK {row['cost']:,.0f} | {row['description'][:40]}" for _, row in df_admin_exp.iterrows()}
                del_id = st.selectbox("Select entry to delete:", df_admin_exp["id"].tolist(), format_func=lambda x: entry_labels[x])
                if st.button("🗑️ Confirm Delete", type="secondary"):
                    write_conn = get_db_connection()
                    cursor = write_conn.cursor()
                    cursor.execute("DELETE FROM admin_expenses WHERE id = %s", (del_id,))
                    write_conn.commit()
                    write_conn.close()
                    log_action(st.session_state.user, f"Deleted admin expense ID {del_id}.")
                    st.warning(f"Entry #{del_id} deleted.")
                    st.rerun()

    conn.close()
    st.stop()


# =============================================================================
# SECTION 4: FLEET REGISTRY
# =============================================================================
elif menu == "🚘 Fleet Registry" and st.session_state.role == "Admin":
    conn = get_db_connection()
    st.title("🚘 Fleet Asset Registry")
    st.subheader("Register Fleet Asset or Machinery Equipment")

    if "asset_success_msg" in st.session_state:
        st.success(st.session_state.asset_success_msg)
        del st.session_state.asset_success_msg

    with st.form("new_vehicle"):
        col_reg1, col_reg2 = st.columns(2)
        plate  = col_reg1.text_input("Asset ID Tag / Registration Plate:")
        m_name = col_reg1.text_input("Make, Model & Specifics:")
        color  = col_reg1.text_input("Asset Color:")
        v_type = col_reg2.selectbox("Asset Classification Category:", ["Standard Car","EV (Electric Vehicle)","Heavy Machinery","Drilling Rig Equipment","Other Auxiliary Gear"])

        if st.form_submit_button("Register Fleet Asset"):
            if plate.strip() and m_name.strip():
                try:
                    write_conn = get_db_connection()
                    cursor = write_conn.cursor()
                    cursor.execute("INSERT INTO vehicles (reg_number, model, color, vehicle_type, status) VALUES (%s,%s,%s,%s,'Available')", (plate.strip().upper(), m_name.strip(), color.strip(), v_type))
                    write_conn.commit()
                    write_conn.close()
                    log_action(st.session_state.user, f"Registered asset: {plate} [{v_type}].")
                    st.session_state.asset_success_msg = f"🎉 Asset [{plate.upper()}] registered successfully."
                    st.rerun()
                except Exception as e:
                    st.error(f"Asset ID '{plate.upper()}' may already exist: {e}")
            else:
                st.warning("Asset ID and description are required.")

    st.markdown("---")
    st.subheader("📋 Core Infrastructure Asset Register")
    df_veh = pd.read_sql_query('SELECT reg_number AS "Asset Code", vehicle_type AS "Classification Type", model AS "Model Details", color AS "Color Scheme", status AS "Operational Yard Status" FROM vehicles', conn)
    st.dataframe(df_veh, use_container_width=True)

    conn.close()
    st.stop()


# =============================================================================
# SECTION 5: ADMIN PANEL
# =============================================================================
elif menu == "🛡️ Admin Panel" and st.session_state.role == "Admin":
    conn = get_db_connection()
    # Purge ghost seed rows on the same connection before any reads
    _cur = conn.cursor()
    _cur.execute("DELETE FROM users WHERE username = 'username' OR role = 'role'")
    _cur.execute("DELETE FROM audit_log WHERE username = 'username' OR action = 'action' OR timestamp = 'timestamp'")
    conn.commit()
    st.title("🛡️ Admin Configuration Dashboard")
    tab_roles, tab_audit = st.tabs(["👥 User Security Directory", "📜 System Security Audit Log"])

    with tab_roles:
        st.subheader("Create New User Account")
        with st.form("add_user"):
            new_username  = st.text_input("Username:")
            new_password  = st.text_input("Password:", type="password")
            assigned_role = st.selectbox("Role:", ["General","Admin"])

            if st.form_submit_button("Create User"):
                if new_username.strip() and new_password:
                    if len(new_password) < 8:
                        st.error("Password must be at least 8 characters.")
                    else:
                        try:
                            write_conn = get_db_connection()
                            cursor = write_conn.cursor()
                            cursor.execute("INSERT INTO users (username, password_hash, role, is_active) VALUES (%s, %s, %s, 1)", (new_username.strip(), hash_password(new_password), assigned_role))
                            write_conn.commit()
                            write_conn.close()
                            log_action(st.session_state.user, f"Created user '{new_username}'.")
                            st.success(f"User '{new_username}' created.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Username '{new_username}' may already exist: {e}")
                else:
                    st.error("Username and password are required.")

        st.markdown("---")
        st.subheader("All Users")

        df_users = pd.read_sql_query(
            "SELECT username, role, is_active FROM users WHERE username IS NOT NULL AND username != '' AND username <> 'username' AND role <> 'role'",
            conn
        )

        for row_idx, u_row in df_users.iterrows():
            badge = "🟢 Active" if u_row['is_active'] == 1 else "🔴 Deactivated"
            with st.expander(f"👤 {u_row['username']} ({u_row['role']}) — {badge}"):
                col_r, col_p, col_d = st.columns([2,3,2])
                is_self = u_row["username"] == st.session_state.user

                role_options = ["General","Admin"]
                current_role = u_row["role"] if u_row["role"] in role_options else "General"
                new_role = col_r.selectbox("Role:", role_options, index=role_options.index(current_role), key=f"role_sel_{row_idx}_{u_row['username']}", disabled=is_self or u_row['is_active'] == 0)
                if col_r.button("💾 Save Role", key=f"btn_role_{row_idx}_{u_row['username']}", disabled=is_self or u_row['is_active'] == 0):
                    if new_role != u_row["role"]:
                        write_conn = get_db_connection()
                        cursor = write_conn.cursor()
                        cursor.execute("UPDATE users SET role = %s WHERE username = %s", (new_role, u_row["username"]))
                        write_conn.commit()
                        write_conn.close()
                        log_action(st.session_state.user, f"Changed role of '{u_row['username']}' to {new_role}.")
                        st.success("Role updated.")
                        st.rerun()
                    else:
                        st.info("No change — role is already set to that value.")

                new_pass_input = col_p.text_input("New Password (Admin Override):", type="password", key=f"pass_over_{row_idx}_{u_row['username']}", disabled=u_row['is_active'] == 0)
                if col_p.button("🔄 Reset Password", key=f"btn_reset_{row_idx}_{u_row['username']}", disabled=u_row['is_active'] == 0):
                    if len(new_pass_input) < 8:
                        st.error("Password must be at least 8 characters.")
                    else:
                        write_conn = get_db_connection()
                        cursor = write_conn.cursor()
                        cursor.execute("UPDATE users SET password_hash = %s WHERE username = %s", (hash_password(new_pass_input), u_row["username"]))
                        write_conn.commit()
                        write_conn.close()
                        log_action(st.session_state.user, f"Reset password for '{u_row['username']}'.")
                        st.success(f"Password updated for [{u_row['username']}].")
                        if is_self:
                            trigger_logout()

                col_d.markdown("<br>", unsafe_allow_html=True)
                if u_row['is_active'] == 1:
                    if col_d.button("🛑 Deactivate", key=f"btn_deact_{row_idx}_{u_row['username']}", disabled=is_self):
                        write_conn = get_db_connection()
                        cursor = write_conn.cursor()
                        cursor.execute("UPDATE users SET is_active = 0 WHERE username = %s", (u_row["username"],))
                        write_conn.commit()
                        write_conn.close()
                        log_action(st.session_state.user, f"Deactivated '{u_row['username']}'.")
                        st.warning(f"Account '{u_row['username']}' deactivated.")
                        st.rerun()
                else:
                    if col_d.button("✅ Reactivate", key=f"btn_react_{row_idx}_{u_row['username']}"):
                        write_conn = get_db_connection()
                        cursor = write_conn.cursor()
                        cursor.execute("UPDATE users SET is_active = 1 WHERE username = %s", (u_row["username"],))
                        write_conn.commit()
                        write_conn.close()
                        log_action(st.session_state.user, f"Reactivated '{u_row['username']}'.")
                        st.success(f"Account '{u_row['username']}' reactivated.")
                        st.rerun()

    with tab_audit:
        st.subheader("System Access Log Ledgers")

        # One-click purge button for ghost rows (runs a direct DELETE on a fresh connection)
        if st.button("🧹 Purge Ghost Rows", key="btn_purge_ghost"):
            try:
                _pc = get_db_connection()
                _pcur = _pc.cursor()
                _pcur.execute("""
                    DELETE FROM audit_log
                    WHERE username = 'username'
                       OR action   = 'action'
                       OR timestamp = 'timestamp'
                       OR username IS NULL
                       OR action IS NULL
                """)
                deleted = _pcur.rowcount
                _pc.commit()
                _pc.close()
                st.session_state["main_nav"] = "🛡️ Admin Panel"
                st.toast(f"✅ Purged {deleted} ghost row(s).", icon="🧹")
                st.rerun()
            except Exception as ex:
                st.error(f"Purge failed: {ex}")

        # Load all rows then filter ghost entries in Python (immune to SQL transaction isolation)
        df_audit_raw = pd.read_sql_query("SELECT * FROM audit_log ORDER BY id DESC", conn)
        df_audit = df_audit_raw[
            df_audit_raw['username'].notna() &
            (df_audit_raw['username'].str.strip() != 'username') &
            (df_audit_raw['username'].str.strip() != '') &
            df_audit_raw['action'].notna() &
            (df_audit_raw['action'].str.strip() != 'action') &
            (df_audit_raw['action'].str.strip() != '')
        ].reset_index(drop=True)
        st.caption(f"Showing {len(df_audit)} real entries (filtered {len(df_audit_raw) - len(df_audit)} ghost rows)")
        st.dataframe(df_audit, use_container_width=True)

    conn.close()
    st.stop()
