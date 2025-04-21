from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import MySQLdb.cursors
import logging
from datetime import datetime
import os
from werkzeug.utils import secure_filename

# Setup logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure secret key

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  # Update with your MySQL password
app.config['MYSQL_DB'] = 'db_pengaduan'

# Upload Folder Configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

mysql = MySQL(app)

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Check database connection before each request
@app.before_request
def check_db_connection():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1")
        cur.close()
        logging.debug("Database connection successful")
    except Exception as e:
        flash(f'Gagal terhubung ke database: {str(e)}', 'danger')
        logging.error(f"Database connection failed: {str(e)}")

# Helper function to fetch location data
def get_location_baru_data():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT DISTINCT province FROM location ORDER BY province")
    provinces = [row['province'] for row in cur.fetchall()]
    
    cur.execute("SELECT DISTINCT province, regency FROM location ORDER BY regency")
    regencies = cur.fetchall()
    
    cur.execute("SELECT DISTINCT regency, subdistrict FROM location ORDER BY subdistrict")
    subdistricts = cur.fetchall()
    
    cur.execute("SELECT DISTINCT subdistrict, village FROM location ORDER BY village")
    villages = cur.fetchall()

    cur.close()
    logging.debug(f"Fetched location data: {len(provinces)} provinces, {len(regencies)} regencies")
    return provinces, regencies, subdistricts, villages

# API Endpoints for Location Data
@app.route('/get_provinces', methods=['GET'])
def get_provinces():
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT DISTINCT province FROM location ORDER BY province")
        provinces = [row['province'] for row in cur.fetchall()]
        cur.close()
        return jsonify(provinces)
    except Exception as e:
        logging.error(f"Error fetching provinces: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_regencies/<province>', methods=['GET'])
def get_regencies(province):
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT DISTINCT regency FROM location WHERE province = %s ORDER BY regency", (province,))
        regencies = [row['regency'] for row in cur.fetchall()]
        cur.close()
        return jsonify(regencies)
    except Exception as e:
        logging.error(f"Error fetching regencies: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_subdistricts/<regency>', methods=['GET'])
def get_subdistricts(regency):
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT DISTINCT subdistrict FROM location WHERE regency = %s ORDER BY subdistrict", (regency,))
        subdistricts = [row['subdistrict'] for row in cur.fetchall()]
        cur.close()
        return jsonify(subdistricts)
    except Exception as e:
        logging.error(f"Error fetching subdistricts: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/get_villages/<subdistrict>', methods=['GET'])
def get_villages(subdistrict):
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT DISTINCT village FROM location WHERE subdistrict = %s ORDER BY village", (subdistrict,))
        villages = [row['village'] for row in cur.fetchall()]
        cur.close()
        return jsonify(villages)
    except Exception as e:
        logging.error(f"Error fetching villages: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([name, email, password, confirm_password]):
            flash('Semua field harus diisi!', 'danger')
            logging.warning("Registrasi gagal: Field tidak lengkap")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Password dan konfirmasi tidak cocok.', 'danger')
            logging.warning("Registrasi gagal: Password tidak cocok")
            return redirect(url_for('register'))

        try:
            cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            existing_user = cur.fetchone()

            if existing_user:
                flash('Email sudah terdaftar.', 'danger')
                logging.warning(f"Registrasi gagal: Email {email} sudah terdaftar")
                cur.close()
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password)
            role = 'masyarakat'

            cur.execute(
                "INSERT INTO users (name, email, password, role ) VALUES (%s, %s, %s, %s)",
                (name, email, hashed_password, role)
            )
            mysql.connection.commit()
            logging.debug(f"Query INSERT untuk {email} berhasil dieksekusi")

            cur.execute("SELECT id, role FROM users WHERE email = %s", (email,))
            new_user = cur.fetchone()
            if new_user and new_user['role'] == 'masyarakat':
                logging.info(f"Registrasi berhasil: {email} disimpan dengan role '{new_user['role']}' dan ID {new_user['id']}")
                flash('Registrasi berhasil sebagai masyarakat! Silakan login.', 'success')
                cur.close()
                return redirect(url_for('login'))
            else:
                logging.error(f"Registrasi gagal: Role untuk {email} tidak disimpan sebagai 'masyarakat'. Data ditemukan: {new_user}")
                flash('Terjadi kesalahan saat menyimpan role. Silakan coba lagi.', 'danger')
                mysql.connection.rollback()
                cur.close()
                return redirect(url_for('register'))

        except Exception as e:
            logging.error(f"Database error selama registrasi untuk {email}: {str(e)}")
            flash(f'Error database: {str(e)}', 'danger')
            mysql.connection.rollback()
            cur.close()
            return redirect(url_for('register'))

    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password_input = request.form.get('password')
        logging.debug(f"Login attempt with email: {email}")

        if not email or not password_input:
            flash('Email dan password harus diisi!', 'danger')
            return render_template('login.html')

        try:
            cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cur.execute("""
                SELECT u.*, sp.location_id 
                FROM users u 
                LEFT JOIN staff_provinces sp ON u.id = sp.user_id 
                WHERE u.email = %s
            """, (email,))
            user = cur.fetchone()
            cur.close()
        except Exception as e:
            flash(f'Error database: {str(e)}', 'danger')
            logging.error(f"Database error during login: {str(e)}")
            return render_template('login.html')

        if user:
            if check_password_hash(user['password'], password_input):
                session['user_id'] = user['id']
                session['name'] = user['name']
                session['role'] = user['role']
                session['email'] = user['email']
                session['location_id'] = user.get('location_id')
                flash('Login berhasil!', 'success')
                logging.info(f"User {email} logged in successfully")

                if user['role'] == 'masyarakat':
                    return redirect(url_for('dashboard_user'))
                elif user['role'] == 'petugas':
                    return redirect(url_for('dashboard_petugas'))
                elif user['role'] == 'admin':
                    return redirect(url_for('dashboard_admin'))
            else:
                flash('Password salah', 'danger')
                logging.warning(f"Failed login attempt for {email}: incorrect password")
        else:
            flash('Email tidak ditemukan!', 'danger')
            logging.warning(f"Failed login attempt: email {email} not found")
    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Berhasil logout', 'info')
    logging.info("User logged out")
    return redirect(url_for('index'))

# Home
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for(f'dashboard_user'))
    
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute(
            """
            SELECT id, description, type, province, regency, subdistrict, village, statement, created_at, voting, views, image
            FROM reports
            """
        )
        all_laporan = cur.fetchall()
        cur.close()
        provinces, regencies, subdistricts, villages = get_location_baru_data()
        return render_template('dashboard_guest.html', all_laporan=all_laporan, provinces=provinces, regencies=regencies, subdistricts=subdistricts, villages=villages)
    except Exception as e:
        flash(f'Error database: {str(e)}', 'danger')
        logging.error(f"Database error during index: {str(e)}")
        return render_template('dashboard_guest.html', all_laporan=[])

# Tambah Laporan Form (GET)
@app.route('/tambah_laporan', methods=['GET'])
def tambah_laporan_form():
    if 'user_id' not in session or session['role'] != 'masyarakat':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('login'))
    
    provinces, regencies, subdistricts, villages = get_location_baru_data()
    logging.debug(f"Rendering tambah_pengaduan.html with {len(provinces)} provinces")
    return render_template('tambah_pengaduan.html', 
                         provinces=provinces, 
                         regencies=regencies, 
                         subdistricts=subdistricts, 
                         villages=villages)

# Tambah Laporan (POST)
@app.route('/tambah_laporan', methods=['POST'])
def tambah_laporan():
    if 'user_id' not in session or session['role'] != 'masyarakat':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('login'))

    description = request.form.get('description')
    type = request.form.get('type')
    province = request.form.get('province')
    regency = request.form.get('regency')
    subdistrict = request.form.get('subdistrict')
    village = request.form.get('village')

    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute(
            "SELECT id FROM location WHERE province = %s AND regency = %s AND subdistrict = %s AND village = %s",
            (province, regency, subdistrict, village)
        )
        location = cur.fetchone()
        cur.close()
        if not location:
            flash('Lokasi tidak valid. Silakan pilih lokasi yang tersedia.', 'danger')
            return redirect(url_for('tambah_laporan_form'))
    except Exception as e:
        flash(f'Error validating location: {str(e)}', 'danger')
        logging.error(f"Database error validating location: {str(e)}")
        return redirect(url_for('tambah_laporan_form'))

    if not all([description, type, province, regency, subdistrict, village]):
        flash('Semua field harus diisi!', 'danger')
        return redirect(url_for('tambah_laporan_form'))

    image = None
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image = f"/static/uploads/{filename}"

    try:
        cur = mysql.connection.cursor()
        current_time = datetime.now()
        cur.execute(
            """
            INSERT INTO reports (user_id, description, type, province, regency, subdistrict, village, statement, created_at, updated_at, image)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (session['user_id'], description, type, province, regency, subdistrict, village, 'Menunggu Verifikasi', current_time, current_time, image)
        )
        mysql.connection.commit()
        cur.close()
        flash('Laporan berhasil ditambahkan!', 'success')
        logging.info(f"Laporan baru ditambahkan oleh user {session['email']}")
    except Exception as e:
        flash(f'Error database: {str(e)}', 'danger')
        logging.error(f"Database error during tambah_laporan: {str(e)}")
    
    return redirect(url_for('dashboard_user'))

# List Laporan
@app.route('/list_laporan')
def list_laporan():
    if 'user_id' not in session or session['role'] != 'masyarakat':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('login'))
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute(
            """
            SELECT id, description, type, province, regency, subdistrict, village, statement, created_at, voting, views, image
            FROM reports WHERE user_id = %s
            """,
            (session['user_id'],)
        )
        laporan_list = cur.fetchall()
        cur.close()
        return render_template('list_laporan.html', laporan_list=laporan_list)
    except Exception as e:
        flash(f'Error database: {str(e)}', 'danger')
        logging.error(f"Database error during list_laporan: {str(e)}")
        return redirect(url_for('dashboard_user'))

# Cari Laporan
@app.route('/cari_laporan', methods=['POST'])
def cari_laporan():
    province = request.form.get('province')
    regency = request.form.get('regency')
    subdistrict = request.form.get('subdistrict')
    village = request.form.get('village')

    query = """
        SELECT 
            r.id, 
            r.description, 
            r.type, 
            r.province, 
            r.regency, 
            r.subdistrict, 
            r.village, 
            r.statement, 
            r.created_at, 
            r.voting, 
            r.views, 
            r.image,
            res.response_status
        FROM reports r
        LEFT JOIN (
            SELECT report_id, response_status
            FROM responses
            WHERE (report_id, created_at) IN (
                SELECT report_id, MAX(created_at)
                FROM responses
                GROUP BY report_id
            )
        ) res ON r.id = res.report_id
        WHERE 1=1
    """
    params = []
    
    if province:
        query += " AND r.province = %s"
        params.append(province)
    if regency:
        query += " AND r.regency = %s"
        params.append(regency)
    if subdistrict:
        query += " AND r.subdistrict = %s"
        params.append(subdistrict)
    if village:
        query += " AND r.village = %s"
        params.append(village)

    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute(query, params)
        laporan_list = cur.fetchall()
        cur.close()
        provinces, regencies, subdistricts, villages = get_location_baru_data()

        if 'user_id' in session and session['role'] == 'masyarakat':
            cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cur.execute(
                """
                SELECT 
                    r.id, 
                    r.description, 
                    r.type, 
                    r.province, 
                    r.regency, 
                    r.subdistrict, 
                    r.village, 
                    r.statement, 
                    r.created_at, 
                    r.voting, 
                    r.views, 
                    r.image,
                    res.response_status
                FROM reports r
                LEFT JOIN (
                    SELECT report_id, response_status
                    FROM responses
                    WHERE (report_id, created_at) IN (
                        SELECT report_id, MAX(created_at)
                        FROM responses
                        GROUP BY report_id
                    )
                ) res ON r.id = res.report_id
                WHERE r.user_id = %s
                """,
                (session['user_id'],)
            )
            user_laporan = cur.fetchall()
            cur.close()
            return render_template(
                'dashboard_user.html',
                name=session['name'],
                all_laporan=laporan_list,
                user_laporan=user_laporan,
                provinces=provinces,
                regencies=regencies,
                subdistricts=subdistricts,
                villages=villages
            )
        else:
            return render_template(
                'dashboard_guest.html',
                all_laporan=laporan_list,
                provinces=provinces,
                regencies=regencies,
                subdistricts=subdistricts,
                villages=villages
            )
    except Exception as e:
        flash(f'Error database: {str(e)}', 'danger')
        logging.error(f"Database error during cari_laporan: {str(e)}")
        return redirect(url_for('index'))

# Dashboard Pengguna (Masyarakat)
@app.route('/dashboard/user')
def dashboard_user():
    if 'user_id' not in session or session['role'] != 'masyarakat':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('login'))

    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute(
            """
            SELECT 
                r.id, 
                r.description, 
                r.type, 
                r.province, 
                r.regency, 
                r.subdistrict, 
                r.village, 
                r.statement, 
                r.created_at, 
                r.voting, 
                r.views, 
                r.image,
                res.response_status
            FROM reports r
            LEFT JOIN (
                SELECT report_id, response_status
                FROM responses
                WHERE (report_id, created_at) IN (
                    SELECT report_id, MAX(created_at)
                    FROM responses
                    GROUP BY report_id
                )
            ) res ON r.id = res.report_id
            """
        )
        all_laporan = cur.fetchall()

        cur.execute(
            """
            SELECT 
                r.id, 
                r.description, 
                r.type, 
                r.province, 
                r.regency, 
                r.subdistrict, 
                r.village, 
                r.statement, 
                r.created_at, 
                r.voting, 
                r.views, 
                r.image,
                res.response_status
            FROM reports r
            LEFT JOIN (
                SELECT report_id, response_status
                FROM responses
                WHERE (report_id, created_at) IN (
                    SELECT report_id, MAX(created_at)
                    FROM responses
                    GROUP BY report_id
                )
            ) res ON r.id = res.report_id
            WHERE r.user_id = %s
            """,
            (session['user_id'],)
        )
        user_laporan = cur.fetchall()
        cur.close()

        provinces, regencies, subdistricts, villages = get_location_baru_data()

        return render_template(
            'dashboard_user.html',
            name=session['name'],
            all_laporan=all_laporan,
            user_laporan=user_laporan,
            provinces=provinces,
            regencies=regencies,
            subdistricts=subdistricts,
            villages=villages
        )
    except Exception as e:
        flash(f'Error database: {str(e)}', 'danger')
        logging.error(f"Database error during dashboard_user: {str(e)}")
        return redirect(url_for('login'))

# Dashboard Petugas
@app.route('/dashboard/petugas')
def dashboard_petugas():
    if 'user_id' not in session or session['role'] != 'petugas':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('login'))

    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT location_id FROM staff_provinces WHERE user_id = %s", (session['user_id'],))
        location_id = cur.fetchone()

        if not location_id or not location_id['location_id']:
            flash('Data lokasi petugas belum ditentukan. Silakan hubungi admin.', 'danger')
            cur.close()
            return redirect(url_for('login'))

        cur.execute("SELECT province FROM location WHERE id = %s", (location_id['location_id'],))
        petugas = cur.fetchone()
        petugas_province = petugas['province'] if petugas and petugas['province'] else None
        if not petugas_province:
            flash('Provinsi petugas belum ditentukan. Silakan hubungi admin.', 'danger')
            cur.close()
            return redirect(url_for('login'))

        cur.execute(
            """
            SELECT 
                r.id, 
                r.description, 
                r.type, 
                r.province, 
                r.regency, 
                r.subdistrict, 
                r.village, 
                r.statement, 
                r.created_at, 
                r.voting, 
                r.views, 
                r.image,
                res.response_status
            FROM reports r
            LEFT JOIN (
                SELECT report_id, response_status
                FROM responses
                WHERE (report_id, created_at) IN (
                    SELECT report_id, MAX(created_at)
                    FROM responses
                    GROUP BY report_id
                )
            ) res ON r.id = res.report_id
            WHERE r.province = %s
            """,
            (petugas_province,)
        )
        all_laporan = cur.fetchall()
        cur.close()
        provinces, regencies, subdistricts, villages = get_location_baru_data()
        return render_template(
            'dashboard_petugas.html',
            name=session['name'],
            province=petugas_province,
            all_laporan=all_laporan,
            provinces=provinces,
            regencies=regencies,
            subdistricts=subdistricts,
            villages=villages
        )
    except Exception as e:
        flash(f'Error database: {str(e)}', 'danger')
        logging.error(f"Database error saat dashboard_petugas: {str(e)}")
        return redirect(url_for('login'))

# Simpan Tanggapan Petugas
@app.route('/simpan_tanggapan', methods=['POST'])
def simpan_tanggapan():
    if 'user_id' not in session or session['role'] != 'petugas':
        return jsonify({'success': False, 'error': 'Akses ditolak! Silakan login sebagai petugas.'}), 403

    report_id = request.form.get('report_id')
    status = request.form.get('status')
    comment = request.form.get('comment')
    petugas_id = session['user_id']

    if not report_id or not status:
        return jsonify({'success': False, 'error': 'Report ID dan status harus diisi!'}), 400

    try:
        cur = mysql.connection.cursor()
        current_time = datetime.now()
        
        # Insert into responses table
        cur.execute(
            """
            INSERT INTO responses (report_id, response_status, user_id, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (report_id, status, petugas_id, current_time, current_time)
        )
        response_id = cur.lastrowid  # Get the ID of the newly inserted response

        # If there's a comment, insert into response_progress table
        if comment:
            cur.execute(
                """
                INSERT INTO response_progress (response_id, histories, created_at, updated_at)
                VALUES (%s, %s, %s, %s)
                """,
                (response_id, comment, current_time, current_time)
            )

        mysql.connection.commit()
        cur.close()
        logging.info(f"Tanggapan disimpan untuk report_id {report_id} oleh petugas {session['email']}, comment: {comment}")
        return jsonify({'success': True}), 200
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        logging.error(f"Database error saat simpan_tanggapan: {str(e)}")
        return jsonify({'success': False, 'error': f'Error database: {str(e)}'}), 500

# Dashboard Admin
@app.route('/dashboard/admin')
def dashboard_admin():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('login'))

    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Fetch all petugas
        cur.execute(
            """
            SELECT u.id, u.name, u.email, l.province
            FROM users u
            JOIN staff_provinces sp ON u.id = sp.user_id
            JOIN location l ON sp.location_id = l.id
            WHERE u.role = 'petugas'
            """
        )
        petugas_list = cur.fetchall()

        # Fetch statistics for reports and responses
        cur.execute(
            """
            SELECT DATE_FORMAT(created_at, '%Y-%m') AS month, COUNT(*) AS count
            FROM reports
            GROUP BY DATE_FORMAT(created_at, '%Y-%m')
            ORDER BY month
            """
        )
        report_stats = cur.fetchall()

        cur.execute(
            """
            SELECT DATE_FORMAT(r.created_at, '%Y-%m') AS month, COUNT(DISTINCT r.report_id) AS count
            FROM responses r
            WHERE (r.report_id, r.created_at) IN (
                SELECT report_id, MAX(created_at)
                FROM responses
                GROUP BY report_id
            )
            GROUP BY DATE_FORMAT(r.created_at, '%Y-%m')
            ORDER BY month
            """
        )
        response_stats = cur.fetchall()

        # Fetch all provinces for dropdown
        cur.execute("SELECT DISTINCT province FROM location ORDER BY province")
        provinces = [row['province'] for row in cur.fetchall()]

        cur.close()

        # Prepare data for Chart.js
        months = sorted(set([r['month'] for r in report_stats] + [r['month'] for r in response_stats]))
        report_data = {r['month']: r['count'] for r in report_stats}
        response_data = {r['month']: r['count'] for r in response_stats}
        
        chart_data = {
            'labels': [datetime.strptime(m, '%Y-%m').strftime('%b %Y') for m in months],
            'reports': [report_data.get(m, 0) for m in months],
            'responses': [response_data.get(m, 0) for m in months]
        }

        return render_template(
            'dashboard_admin.html',
            name=session['name'],
            petugas_list=petugas_list,
            chart_data=chart_data,
            provinces=provinces
        )
    except Exception as e:
        flash(f'Error database: {str(e)}', 'danger')
        logging.error(f"Database error during dashboard_admin: {str(e)}")
        return redirect(url_for('login'))

# CRUD Operations for Petugas
@app.route('/admin/add_petugas', methods=['POST'])
def add_petugas():
    if 'user_id' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'error': 'Akses ditolak!'}), 403

    nama = request.form.get('nama')
    email = request.form.get('email')
    password = request.form.get('password')
    provinsi = request.form.get('provinsi')

    if not all([nama, email, password, provinsi]):
        return jsonify({'success': False, 'error': 'Semua field harus diisi!'}), 400

    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Check if email exists
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            cur.close()
            return jsonify({'success': False, 'error': 'Email sudah terdaftar!'}), 400

        # Get location_id for province
        cur.execute("SELECT id FROM location WHERE province = %s LIMIT 1", (provinsi,))
        location = cur.fetchone()
        if not location:
            cur.close()
            return jsonify({'success': False, 'error': 'Provinsi tidak valid!'}), 400
        location_id = location['id']

        # Insert new petugas
        hashed_password = generate_password_hash(password)
        cur.execute(
            """
            INSERT INTO users (name, email, password, role```python
            role)
            VALUES (%s, %s, %s, %s)
            """,
            (nama, email, hashed_password, 'petugas')
        )
        user_id = cur.lastrowid

        # Link petugas to province
        cur.execute(
            """
            INSERT INTO staff_provinces (user_id, location_id, created_at, updated_at)
            VALUES (%s, %s, %s, %s)
            """,
            (user_id, location_id, datetime.now(), datetime.now())
        )

        mysql.connection.commit()
        cur.close()
        logging.info(f"Petugas {email} ditambahkan oleh admin {session['email']}")
        return jsonify({'success': True, 'petugas': {'id': user_id, 'name': nama, 'email': email, 'province': provinsi}}), 200
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        logging.error(f"Database error saat add_petugas: {str(e)}")
        return jsonify({'success': False, 'error': f'Error database: {str(e)}'}), 500

@app.route('/admin/edit_petugas/<int:id>', methods=['POST'])
def edit_petugas(id):
    if 'user_id' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'error': 'Akses ditolak!'}), 403

    nama = request.form.get('nama')
    email = request.form.get('email')
    password = request.form.get('password')
    provinsi = request.form.get('provinsi')

    if not all([nama, email, provinsi]):
        return jsonify({'success': False, 'error': 'Semua field wajib diisi!'}), 400

    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        
        # Check if email is taken by another user
        cur.execute("SELECT id FROM users WHERE email = %s AND id != %s", (email, id))
        if cur.fetchone():
            cur.close()
            return jsonify({'success': False, 'error': 'Email sudah digunakan oleh pengguna lain!'}), 400

        # Get location_id for province
        cur.execute("SELECT id FROM location WHERE province = %s LIMIT 1", (provinsi,))
        location = cur.fetchone()
        if not location:
            cur.close()
            return jsonify({'success': False, 'error': 'Provinsi tidak valid!'}), 400
        location_id = location['id']

        # Update user
        if password:
            hashed_password = generate_password_hash(password)
            cur.execute(
                """
                UPDATE users
                SET name = %s, email = %s, password = %s
                WHERE id = %s AND role = 'petugas'
                """,
                (nama, email, hashed_password, id)
            )
        else:
            cur.execute(
                """
                UPDATE users
                SET name = %s, email = %s
                WHERE id = %s AND role = 'petugas'
                """,
                (nama, email, id)
            )

        # Update staff_provinces
        cur.execute(
            """
            UPDATE staff_provinces
            SET location_id = %s, updated_at = %s
            WHERE user_id = %s
            """,
            (location_id, datetime.now(), id)
        )

        mysql.connection.commit()
        cur.close()
        logging.info(f"Petugas ID {id} diedit oleh admin {session['email']}")
        return jsonify({'success': True, 'petugas': {'id': id, 'name': nama, 'email': email, 'province': provinsi}}), 200
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        logging.error(f"Database error saat edit_petugas: {str(e)}")
        return jsonify({'success': False, 'error': f'Error database: {str(e)}'}), 500

@app.route('/admin/delete_petugas/<int:id>', methods=['DELETE'])
def delete_petugas(id):
    if 'user_id' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'error': 'Akses ditolak!'}), 403

    try:
        cur = mysql.connection.cursor()
        
        # Delete from staff_provinces
        cur.execute("DELETE FROM staff_provinces WHERE user_id = %s", (id,))
        
        # Delete from users
        cur.execute("DELETE FROM users WHERE id = %s AND role = 'petugas'", (id,))
        
        if cur.rowcount == 0:
            cur.close()
            return jsonify({'success': False, 'error': 'Petugas tidak ditemukan!'}), 404

        mysql.connection.commit()
        cur.close()
        logging.info(f"Petugas ID {id} dihapus oleh admin {session['email']}")
        return jsonify({'success': True}), 200
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        logging.error(f"Database error saat delete_petugas: {str(e)}")
        return jsonify({'success': False, 'error': f'Error database: {str(e)}'}), 500

# Comment Routes
@app.route('/comment/<int:report_id>')
def comment(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute(
        """
        SELECT 
            r.id, 
            r.description, 
            r.type, 
            r.province, 
            r.regency, 
            r.subdistrict, 
            r.village, 
            r.statement, 
            r.created_at, 
            r.voting, 
            r.views, 
            r.image,
            res.response_status
        FROM reports r
        LEFT JOIN (
            SELECT report_id, response_status
            FROM responses
            WHERE (report_id, created_at) IN (
                SELECT report_id, MAX(created_at)
                FROM responses
                GROUP BY report_id
            )
        ) res ON r.id = res.report_id
        WHERE r.id = %s
        """,
        (report_id,)
    )
    laporan = cur.fetchone()
    cur.close()
    
    if not laporan:
        return 'Report not found', 404
    
    return render_template('comment.html', laporan=laporan, session=session)

@app.route('/get_comments/<int:report_id>')
def get_comments(report_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute(
        """
        SELECT c.comment, c.created_at, u.name AS user_name
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.report_id = %s
        ORDER BY c.created_at ASC
        """,
        (report_id,)
    )
    comments = cur.fetchall()
    cur.close()
    
    comment_list = [
        {
            'user_name': comment['user_name'],
            'content': comment['comment'],
            'created_at': comment['created_at'].strftime('%d %B %Y %H:%M')
        }
        for comment in comments
    ]
    return jsonify({'comments': comment_list})

@app.route('/submit_comment', methods=['POST'])
def submit_comment():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'User not logged in'}), 401

    report_id = request.form.get('report_id')
    comment = request.form.get('content')

    if not report_id or not comment:
        return jsonify({'success': False, 'error': 'Missing report_id or comment content'}), 400

    try:
        report_id = int(report_id)
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid report_id'}), 400

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT id FROM reports WHERE id = %s", (report_id,))
    if not cur.fetchone():
        cur.close()
        return jsonify({'success': False, 'error': 'Report not found'}), 404

    current_time = datetime.now()
    cur.execute(
        """
        INSERT INTO comments (user_id, report KU, comment, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (session['user_id'], report_id, comment, current_time, current_time)
    )
    mysql.connection.commit()
    cur.close()

    return jsonify({'success': True})

# Run the application
if __name__ == '__main__':
    app.run(debug=True)