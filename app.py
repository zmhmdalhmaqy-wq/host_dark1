import os
import json
import re
import subprocess
import psutil
import socket
import sys
import hashlib
import secrets
import time
import traceback
import threading
import requests
import signal
import shutil
import zipfile
from datetime import datetime, timedelta
from flask import Flask, send_from_directory, request, jsonify, session, redirect, url_for, render_template_string, make_response
from db_handler import db_handler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, "USERS")
os.makedirs(USERS_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB

# بيانات المسؤول (تم التحديث بناءً على طلب المستخدم)
ADMIN_USERNAME = "Ziad00"
ADMIN_PASSWORD_RAW = "Ziad00"

# ============== PORT MANAGEMENT ==============
USED_PORTS = set()
PORT_RANGE_START = 8100
PORT_RANGE_END = 9000

def load_db():
    """تحميل قاعدة البيانات من MongoDB (أو JSON محلي كبديل)"""
    return db_handler.load_db()

def save_db(db_data):
    """حفظ قاعدة البيانات في MongoDB (أو JSON محلي كبديل)"""
    db_handler.save_db(db_data)

try:
    db = load_db()
except Exception as e:
    print(f"❌ خطأ فادح في تحميل قاعدة البيانات: {e}")
    import traceback
    print(traceback.format_exc())
    db = {"users": {}, "servers": {}, "logs": []} # fallback to empty db to allow app to start


def get_assigned_port():
    """يعطي port ثابت ومخصص لكل سيرفر من نطاق محدد"""
    used = set()
    for srv in db.get("servers", {}).values():
        if srv.get("port"):
            used.add(srv["port"])
    
    for port in range(PORT_RANGE_START, PORT_RANGE_END):
        if port not in used:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                result = s.connect_ex(('127.0.0.1', port))
                s.close()
                if result != 0:
                    return port
            except:
                return port
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

# Process Monitor
def monitor_processes():
    while True:
        try:
            for folder, srv in list(db["servers"].items()):
                if srv.get("status") == "Running" and srv.get("pid"):
                    try:
                        p = psutil.Process(srv["pid"])
                        if not p.is_running() or p.status() == psutil.STATUS_ZOMBIE:
                            db["servers"][folder]["status"] = "Stopped"
                            db["servers"][folder]["pid"] = None
                            save_db(db)
                    except:
                        db["servers"][folder]["status"] = "Stopped"
                        db["servers"][folder]["pid"] = None
                        save_db(db)
        except:
            pass
        time.sleep(10)

threading.Thread(target=monitor_processes, daemon=True).start()

def get_current_user():
    if "username" in session:
        return db["users"].get(session["username"])
    return None

def get_user_servers_dir(username):
    path = os.path.join(USERS_DIR, username, "SERVERS")
    os.makedirs(path, exist_ok=True)
    return path

def is_admin(username):
    if username == ADMIN_USERNAME:
        return True
    u = db["users"].get(username)
    return u.get("is_admin", False) if u else False

# ============== ROUTES ==============

@app.route('/')
def home():
    if 'username' not in session:
        return redirect('/login')
    user = get_current_user()
    if user and user.get("is_admin") or session.get("username") == ADMIN_USERNAME:
        return redirect('/admin')
    return redirect('/dashboard')

@app.route('/login')
def login_page():
    if 'username' in session:
        return redirect('/')
    try:
        with open(os.path.join(BASE_DIR, 'login.html'), 'r', encoding='utf-8') as f:
            return f.read()
    except:
        return "Login page not found"

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    with open(os.path.join(BASE_DIR, 'index.html'), 'r', encoding='utf-8') as f:
        return f.read()

@app.route('/admin')
def admin_panel():
    if 'username' not in session or not is_admin(session['username']):
        return redirect('/login')
    with open(os.path.join(BASE_DIR, 'admin_panel.html'), 'r', encoding='utf-8') as f:
        return f.read()

# ============== AUTH APIs ==============

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    remember_me = data.get("remember_me", False)
    
    # التحقق من حساب المسؤول (RLH55 / OMAROMAR19)
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD_RAW:
        session['username'] = username
        session.permanent = True
        return jsonify({"success": True, "redirect": "/admin", "is_admin": True})
    
    # التحقق من المستخدمين الآخرين في قاعدة البيانات
    user = db["users"].get(username)
    if user and user["password"] == hashlib.sha256(password.encode()).hexdigest():
        session['username'] = username
        session.permanent = True
        user["last_login"] = str(datetime.now())
        save_db(db)
        return jsonify({
            "success": True,
            "redirect": "/admin" if user.get("is_admin") else "/dashboard",
            "is_admin": user.get("is_admin", False)
        })
    
    return jsonify({"success": False, "message": "خطأ في اسم المستخدم أو كلمة المرور"})

@app.route('/api/logout', methods=['GET', 'POST'])
def api_logout():
    session.clear()
    response = make_response(redirect('/login'))
    # حذف جميع الكوكيز لضمان تسجيل الخروج الكامل
    response.delete_cookie('session')
    response.delete_cookie('remember_token')
    return response

@app.route('/api/current_user')
def api_current_user():
    if "username" in session:
        if session["username"] == ADMIN_USERNAME:
            return jsonify({"success": True, "username": ADMIN_USERNAME, "is_admin": True})
        u = db["users"].get(session["username"])
        if u:
            return jsonify({
                "success": True,
                "username": session["username"],
                "is_admin": u.get("is_admin", False)
            })
    return jsonify({"success": False})

# ============== SERVER MANAGEMENT ==============

@app.route('/api/servers')
def list_servers():
    if "username" not in session:
        return jsonify({"success": False}), 401
    
    user_servers = []
    for folder, srv in db["servers"].items():
        if srv["owner"] == session["username"]:
            uptime_str = "0 ثانية"
            if srv.get("status") == "Running" and srv.get("start_time"):
                diff = time.time() - srv["start_time"]
                days = int(diff // 86400)
                hours = int((diff % 86400) // 3600)
                mins = int((diff % 3600) // 60)
                parts = []
                if days > 0: parts.append(f"{days} يوم")
                if hours > 0: parts.append(f"{hours} ساعة")
                if mins > 0: parts.append(f"{mins} دقيقة")
                uptime_str = " و ".join(parts) if parts else "أقل من دقيقة"
                
            user_servers.append({
                "folder": folder,
                "title": srv["name"],
                "subtitle": f"سيرفر {srv.get('type', 'Python')}",
                "startup_file": srv.get("startup_file"),
                "status": srv.get("status", "Stopped"),
                "uptime": uptime_str,
                "port": srv.get("port", "N/A")
            })
    
    user = db["users"].get(session["username"], {"max_servers": 3, "expiry_days": 30})
    max_srv = user.get("max_servers", 3)
    
    return jsonify({
        "success": True,
        "servers": user_servers,
        "stats": {
            "used": len(user_servers),
            "total": max_srv,
            "expiry": user.get("expiry_days", 30)
        }
    })

@app.route('/api/server/add', methods=['POST'])
def add_server():
    if "username" not in session:
        return jsonify({"success": False}), 401
    
    user = db["users"].get(session["username"], {"max_servers": 3})
    user_srv_count = len([s for s in db["servers"].values() if s["owner"] == session["username"]])
    if user_srv_count >= user.get("max_servers", 3):
        return jsonify({"success": False, "message": "وصلت للحد الأقصى من السيرفرات"})
    
    data = request.get_json()
    name = data.get("name", "New Server").strip()
    if not name: name = "Server_" + secrets.token_hex(2)
    
    folder = f"{session['username']}_{re.sub(r'[^a-zA-Z0-9]', '', name)}_{int(time.time())}"
    path = os.path.join(get_user_servers_dir(session["username"]), folder)
    os.makedirs(path, exist_ok=True)
    
    assigned_port = get_assigned_port()
    
    db["servers"][folder] = {
        "name": name,
        "owner": session["username"],
        "path": path,
        "type": "Python",
        "status": "Stopped",
        "created_at": str(datetime.now()),
        "startup_file": "main.py",
        "pid": None,
        "port": assigned_port
    }
    save_db(db)
    return jsonify({"success": True, "message": f"تم إنشاء السيرفر على البورت {assigned_port}"})

@app.route('/api/server/action/<folder>/<action>', methods=['POST'])
def server_action(folder, action):
    if "username" not in session:
        return jsonify({"success": False}), 401
    
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]:
        return jsonify({"success": False, "message": "غير مصرح"})
    
    if action == "start":
        if srv.get("status") == "Running":
            return jsonify({"success": False, "message": "السيرفر يعمل بالفعل"})
        
        main_file = srv.get("startup_file", "main.py")
        file_path = os.path.join(srv["path"], main_file)
        
        if not os.path.exists(file_path):
            for f in ["app.py", "main.py", "index.js", "index.php", "index.html"]:
                if os.path.exists(os.path.join(srv["path"], f)):
                    main_file = f
                    srv["startup_file"] = f
                    file_path = os.path.join(srv["path"], f)
                    break
            else:
                return jsonify({"success": False, "message": "لم يتم العثور على ملف تشغيل"})
        
        port = srv.get("port")
        if not port:
            port = get_assigned_port()
            srv["port"] = port

        log_path = os.path.join(srv["path"], "out.log")
        log_file = open(log_path, "a", encoding='utf-8')
        
        try:
            proc = subprocess.Popen(
                [sys.executable, "-u", main_file],
                cwd=srv["path"],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env={**os.environ, "PORT": str(port)}
            )
            srv["status"] = "Running"
            srv["pid"] = proc.pid
            srv["start_time"] = time.time()
            save_db(db)
            return jsonify({"success": True, "message": "✅ تم تشغيل السيرفر"})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    elif action == "stop":
        if srv.get("pid"):
            try:
                p = psutil.Process(srv["pid"])
                for child in p.children(recursive=True):
                    child.kill()
                p.kill()
            except:
                pass
        srv["status"] = "Stopped"
        srv["pid"] = None
        save_db(db)
        return jsonify({"success": True, "message": "🛑 تم إيقاف السيرفر"})

    elif action == "delete":
        # إيقاف قسري فوري للعملية إذا كانت تعمل
        if srv.get("pid"):
            try:
                p = psutil.Process(srv["pid"])
                if p.is_running():
                    # قتل جميع العمليات الفرعية أولاً
                    for child in p.children(recursive=True):
                        try:
                            child.kill()
                        except:
                            pass
                    # قتل العملية الرئيسية
                    p.kill()
                    # الانتظار قليلاً للتأكد من إغلاق جميع الموارد
                    try:
                        p.wait(timeout=2)
                    except:
                        pass
            except:
                pass
        
        # حذف المجلد بالكامل (حذف قسري فوري)
        if os.path.exists(srv["path"]):
            try:
                # محاولة الحذف العادي أولاً
                shutil.rmtree(srv["path"])
            except:
                # إذا فشل، حاول الحذف القسري عبر الأوامر بقوة
                try:
                    subprocess.run(["rm", "-rf", srv["path"]], timeout=10, capture_output=True, check=False)
                except:
                    try:
                        subprocess.run(["sudo", "rm", "-rf", srv["path"]], timeout=10, capture_output=True, check=False)
                    except:
                        pass
        
        # حذف من قاعدة البيانات
        try:
            del db["servers"][folder]
            save_db(db)
        except:
            pass
        
        srv["status"] = "Stopped"
        srv["pid"] = None
        return jsonify({"success": True, "message": "🗑️ تم حذف السيرفر بنجاح"})

    return jsonify({"success": False})

def get_public_ip():
    try:
        import requests
        return requests.get('https://api.ipify.org', timeout=5).text
    except:
        return "127.0.0.1"

@app.route('/api/server/stats/<folder>')
def get_server_stats(folder):
    if "username" not in session: return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]: return jsonify({"success": False})
    
    status = srv.get("status", "Stopped")
    
    # قراءة السجلات من ملف out.log
    logs = "في انتظار المخرجات..."
    log_path = os.path.join(srv["path"], "out.log")
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # أخذ آخر 500 سطر لضمان ظهور كل شيء
                lines = content.split('\n')
                logs = '\n'.join(lines[-500:])
        except:
            logs = "خطأ في قراءة السجلات"
    
    # معلومات الذاكرة والعملية
    mem_info = "0 MB"
    if srv.get("pid") and status == "Running":
        try:
            p = psutil.Process(srv["pid"])
            mem_mb = p.memory_info().rss / (1024 * 1024)
            mem_info = f"{mem_mb:.1f} MB"
        except:
            pass
    
    # حساب وقت التشغيل
    uptime_str = "0 ثانية"
    if status == "Running" and srv.get("start_time"):
        diff = time.time() - srv["start_time"]
        days = int(diff // 86400)
        hours = int((diff % 86400) // 3600)
        mins = int((diff % 3600) // 60)
        secs = int(diff % 60)
        parts = []
        if days > 0: parts.append(f"{days} يوم")
        if hours > 0: parts.append(f"{hours} ساعة")
        if mins > 0: parts.append(f"{mins} دقيقة")
        if not parts: parts.append(f"{secs} ثانية")
        uptime_str = " و ".join(parts)
    
    return jsonify({
        "success": True,
        "status": status,
        "online_status": "Online" if status == "Running" else "Offline",
        "logs": logs,
        "mem": mem_info,
        "uptime": uptime_str,
        "port": srv.get("port", "--"),
        "ip": get_public_ip()
    })

@app.route('/api/server/console/<folder>')
def get_console(folder):
    if "username" not in session: return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]: return jsonify({"success": False})
    
    log_path = os.path.join(srv["path"], "out.log")
    if os.path.exists(log_path):
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            return jsonify({"success": True, "lines": lines[-100:]})
    return jsonify({"success": True, "lines": ["لم يتم العثور على سجلات"]})

@app.route('/api/server/install/<folder>', methods=['POST'])
def install_requirements(folder):
    if "username" not in session: return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]: return jsonify({"success": False})
    
    req_file = os.path.join(srv["path"], "requirements.txt")
    if os.path.exists(req_file):
        try:
            log_path = os.path.join(srv["path"], "out.log")
            with open(req_file, 'r', encoding='utf-8') as rf:
                packages = [line.strip() for line in rf.readlines() if line.strip() and not line.startswith('#')]
            
            log_file = open(log_path, "a", encoding='utf-8', buffering=1)
            
            # بدء عملية التثبيت بعرض المخرجات الخام فقط مع تفاصيل الأخطاء
            proc = subprocess.Popen(
                [sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--no-cache-dir", "-v"],
                cwd=srv["path"],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True
            )
            
            def monitor_install(proc, log_file, folder):
                try:
                    proc.wait()
                    if proc.returncode == 0:
                        # بعد التثبيت بنجاح، بدء البوت تلقائياً
                        try:
                            with app.app_context():
                                server_action(folder, "start")
                        except Exception as e:
                            log_file.write(f"\n[ERROR] فشل بدء البوت: {str(e)}\n")
                    else:
                        log_file.write(f"\n[ERROR] فشل التثبيت برمز الخروج: {proc.returncode}\n")
                except Exception as e:
                    log_file.write(f"\n[ERROR] خطأ أثناء المراقبة: {str(e)}\n")
                finally:
                    log_file.flush()
                    log_file.close()
            
            threading.Thread(target=monitor_install, args=(proc, log_file, folder), daemon=True).start()
            return jsonify({"success": True, "message": "📦 بدأ التثبيت، تابع الكونسول"})
        except Exception as e:
            import traceback
            error_msg = f"خطأ في التثبيت: {str(e)}\n{traceback.format_exc()}"
            return jsonify({"success": False, "message": error_msg})
    return jsonify({"success": False, "message": "❌ requirements.txt غير موجود"})

# ============== FILE MANAGEMENT APIs ==============

@app.route('/api/files/list/<folder>')
def list_server_files(folder):
    if "username" not in session: return jsonify([]), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]: return jsonify([])
    
    path = srv["path"]
    files = []
    try:
        for f in os.listdir(path):
            fpath = os.path.join(path, f)
            stat = os.stat(fpath)
            size_bytes = stat.st_size
            if size_bytes < 1024:
                size_str = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size_str = f"{size_bytes / 1024:.1f} KB"
            else:
                size_str = f"{size_bytes / (1024*1024):.1f} MB"
            files.append({
                "name": f,
                "size": size_str,
                "is_dir": os.path.isdir(fpath),
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
            })
    except Exception as e:
        return jsonify([])
    return jsonify(sorted(files, key=lambda x: (not x['is_dir'], x['name'].lower())))

@app.route('/api/files/content/<folder>/<filename>')
def get_file_content(folder, filename):
    if "username" not in session: return jsonify({"content": ""}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]: return jsonify({"content": ""})
    
    if '..' in filename: return jsonify({"content": ""})
    fpath = os.path.join(srv["path"], filename)
    if not os.path.exists(fpath) or os.path.isdir(fpath):
        return jsonify({"content": ""})
    try:
        with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
            return jsonify({"content": f.read()})
    except:
        return jsonify({"content": "[ملف ثنائي - لا يمكن عرضه]"})

@app.route('/api/files/save/<folder>/<filename>', methods=['POST'])
def save_file_content(folder, filename):
    if "username" not in session: return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]: return jsonify({"success": False})
    
    if '..' in filename: return jsonify({"success": False, "message": "اسم ملف غير صالح"})
    data = request.get_json()
    content = data.get("content", "")
    fpath = os.path.join(srv["path"], filename)
    try:
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(content)
        return jsonify({"success": True, "message": "✅ تم حفظ الملف"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/files/create/<folder>', methods=['POST'])
def create_file(folder):
    if "username" not in session: return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]: return jsonify({"success": False})
    
    data = request.get_json()
    filename = data.get("filename", "").strip()
    content = data.get("content", "")
    if not filename or '..' in filename:
        return jsonify({"success": False, "message": "اسم ملف غير صالح"})
    fpath = os.path.join(srv["path"], filename)
    try:
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(content)
        return jsonify({"success": True, "message": f"✅ تم إنشاء {filename}"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/files/delete/<folder>', methods=['POST'])
def delete_files(folder):
    if "username" not in session: return jsonify({"success": False, "message": "غير مصرح"}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]: return jsonify({"success": False, "message": "غير مصرح"})
    
    data = request.get_json() or {}
    # قبول name أو names أو قائمة
    names = data.get("names", data.get("name", []))
    if isinstance(names, str): names = [names]
    if not names:
        return jsonify({"success": False, "message": "لم يتم تحديد ملفات"})
    
    deleted = 0
    errors = []
    for name in names:
        if not name or '..' in name or '/' in name: continue
        fpath = os.path.join(srv["path"], name)
        try:
            if os.path.isdir(fpath):
                # حذف قسري للمجلد
                try:
                    shutil.rmtree(fpath)
                except:
                    subprocess.run(["rm", "-rf", fpath], timeout=5, capture_output=True)
                deleted += 1
            elif os.path.exists(fpath):
                # حذف قسري للملف
                try:
                    os.remove(fpath)
                except:
                    subprocess.run(["rm", "-f", fpath], timeout=5, capture_output=True)
                deleted += 1
            else:
                errors.append(f"{name}: غير موجود")
        except Exception as e:
            errors.append(f"{name}: {str(e)}")
    
    if deleted > 0:
        return jsonify({"success": True, "message": f"🗑️ تم حذف {deleted} ملف بنجاح"})
    else:
        return jsonify({"success": False, "message": "فشل الحذف: " + ", ".join(errors)})

@app.route('/api/files/rename/<folder>', methods=['POST'])
def rename_file(folder):
    if "username" not in session: return jsonify({"success": False}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]: return jsonify({"success": False})
    
    data = request.get_json()
    old_name = data.get("old_name", "").strip()
    new_name = data.get("new_name", "").strip()
    if not old_name or not new_name or '..' in old_name or '..' in new_name:
        return jsonify({"success": False, "message": "اسم ملف غير صالح"})
    old_path = os.path.join(srv["path"], old_name)
    new_path = os.path.join(srv["path"], new_name)
    try:
        os.rename(old_path, new_path)
        return jsonify({"success": True, "message": f"✅ تم تغيير الاسم إلى {new_name}"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/files/upload/<folder>', methods=['POST'])
def upload_files(folder):
    if "username" not in session: return jsonify({"success": False, "message": "غير مصرح"}), 401
    srv = db["servers"].get(folder)
    if not srv or srv["owner"] != session["username"]: return jsonify({"success": False, "message": "غير مصرح"})
    
    # التأكد من وجود مجلد السيرفر
    if not os.path.exists(srv["path"]):
        try:
            os.makedirs(srv["path"], exist_ok=True)
        except Exception as e:
            return jsonify({"success": False, "message": f"خطأ في إنشاء المجلد: {str(e)}"})
    
    files = request.files.getlist('files[]')
    if not files:
        return jsonify({"success": False, "message": "لا توجد ملفات"})
    
    uploaded = 0
    errors = []
    
    for f in files:
        try:
            if not f or not f.filename:
                errors.append("اسم ملف فارغ")
                continue
            
            # منع المسارات الخطرة
            if '..' in f.filename or f.filename.startswith('/'):
                errors.append(f"{f.filename}: اسم ملف غير صالح")
                continue
            
            save_path = os.path.join(srv["path"], f.filename)
            
            # حفظ الملف مع معالجة الأخطاء
            try:
                f.save(save_path)
            except Exception as e:
                errors.append(f"{f.filename}: فشل الحفظ - {str(e)}")
                continue
            
            # فك ضغط ZIP تلقائياً
            if f.filename.lower().endswith('.zip'):
                try:
                    with zipfile.ZipFile(save_path, 'r') as z:
                        z.extractall(srv["path"])
                    os.remove(save_path)
                except Exception as e:
                    errors.append(f"{f.filename}: فشل فك الضغط - {str(e)}")
            
            uploaded += 1
        except Exception as e:
            errors.append(f"{f.filename}: {str(e)}")
    
    if uploaded > 0:
        msg = f"✅ تم رفع {uploaded} ملف"
        if errors:
            msg += f" (مع {len(errors)} أخطاء)"
        return jsonify({"success": True, "message": msg, "uploaded": uploaded, "errors": errors})
    else:
        return jsonify({"success": False, "message": "فشل رفع جميع الملفات", "errors": errors})

# ============== ADMIN APIs ==============

@app.route('/api/admin/users')
def admin_users():
    if "username" not in session or not is_admin(session["username"]):
        return jsonify({}), 403
    
    users_list = []
    for uname, udata in db["users"].items():
        users_list.append({
            "username": uname,
            "is_admin": udata.get("is_admin", False),
            "created_at": udata.get("created_at"),
            "last_login": udata.get("last_login"),
            "max_servers": udata.get("max_servers", 3),
            "expiry_days": udata.get("expiry_days", 30)
        })
    return jsonify({"success": True, "users": users_list})

@app.route('/api/admin/create-user', methods=['POST'])
def admin_create_user():
    if "username" not in session or not is_admin(session["username"]):
        return jsonify({}), 403
    
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    max_servers = int(data.get("max_servers", 3))
    expiry_days = int(data.get("expiry_days", 30))
    
    if username in db["users"]:
        return jsonify({"success": False, "message": "المستخدم موجود بالفعل"})
        
    db["users"][username] = {
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "is_admin": False,
        "created_at": str(datetime.now()),
        "max_servers": max_servers,
        "expiry_days": expiry_days
    }
    save_db(db)
    return jsonify({"success": True, "message": "✅ تم إنشاء الحساب"})

@app.route('/api/admin/delete-user', methods=['POST'])
def admin_delete_user():
    if "username" not in session or not is_admin(session["username"]):
        return jsonify({"success": False, "message": "غير مصرح"}), 403
    
    data = request.get_json()
    username = data.get("username", "").strip()
    
    if not username or username == "OMAR_ADMIN":
        return jsonify({"success": False, "message": "لا يمكن حذف هذا المستخدم"})
    
    if username in db["users"]:
        # حذف سيرفرات المستخدم
        servers_to_delete = [fid for fid, srv in db["servers"].items() if srv["owner"] == username]
        for fid in servers_to_delete:
            srv = db["servers"][fid]
            # إيقاف السيرفر إذا كان يعمل
            if srv.get("status") == "Running" and srv.get("pid"):
                try:
                    p = psutil.Process(srv["pid"])
                    p.terminate()
                except:
                    pass
            # حذف مجلد السيرفر
            if os.path.exists(srv["path"]):
                try:
                    shutil.rmtree(srv["path"])
                except:
                    pass
            # حذف من قاعدة البيانات
            del db["servers"][fid]
            
        # حذف المستخدم من قاعدة البيانات
        del db["users"][username]
        save_db(db)
        return jsonify({"success": True, "message": f"🗑️ تم حذف المستخدم {username} وجميع بياناته"})
    
    return jsonify({"success": False, "message": "المستخدم غير موجود"})

# Metrics API
@app.route('/api/system/metrics')
def get_metrics():
    return jsonify({
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent
    })

@app.route('/api/ping', methods=['GET', 'POST'])
def ping():
    return jsonify({"status": "pong", "timestamp": str(datetime.now())}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
