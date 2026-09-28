from flask import Flask, request, jsonify, redirect
import os, secrets
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2.extras import RealDictCursor

app=Flask(__name__)
DATABASE_URL=os.getenv("DATABASE_URL","").strip()
ADMIN_PASSWORD=os.getenv("DEEWARYN_ADMIN_PASSWORD","admin123")

TABLES={
"properties":["code","purpose","ptype","location","area","price","beds","baths","owner","phone","status","notes"],
"contacts":["name","phone","email","ctype","budget","location","requirement","source","stage","assigned","followup","notes"],
"deals":["title","client","property_code","stage","deal_value","commission","assigned","next_action","notes"],
"tasks":["title","related_to","due","priority","status","assigned","notes"],
"employees":["name","phone","email","role","salary","visits","calls","properties","deals","expense","status","notes"],
"ledger":["dt","etype","category","source","amount","ref","notes"],
"rent":["property_code","tenant","tenant_phone","owner","monthly_rent","security","due_day","start_date","agreement_end","last_paid","status","notes"],
"projects":["name","ptype","client","phone","location","contract","spent","progress","status","start_date","end_date","notes"],
"maintenance":["title","client","phone","location","category","priority","assigned","status","estimate","spent","notes"]
}

SCHEMA=[
"""CREATE TABLE IF NOT EXISTS properties(id BIGSERIAL PRIMARY KEY,code TEXT,purpose TEXT,ptype TEXT,location TEXT,area TEXT,price DOUBLE PRECISION,beds INTEGER,baths INTEGER,owner TEXT,phone TEXT,status TEXT,notes TEXT,created TEXT)""",
"""CREATE TABLE IF NOT EXISTS contacts(id BIGSERIAL PRIMARY KEY,name TEXT,phone TEXT,email TEXT,ctype TEXT,budget DOUBLE PRECISION,location TEXT,requirement TEXT,source TEXT,stage TEXT,assigned TEXT,followup TEXT,notes TEXT,created TEXT)""",
"""CREATE TABLE IF NOT EXISTS deals(id BIGSERIAL PRIMARY KEY,title TEXT,client TEXT,property_code TEXT,stage TEXT,deal_value DOUBLE PRECISION,commission DOUBLE PRECISION,assigned TEXT,next_action TEXT,notes TEXT,created TEXT)""",
"""CREATE TABLE IF NOT EXISTS tasks(id BIGSERIAL PRIMARY KEY,title TEXT,related_to TEXT,due TEXT,priority TEXT,status TEXT,assigned TEXT,notes TEXT,created TEXT)""",
"""CREATE TABLE IF NOT EXISTS employees(id BIGSERIAL PRIMARY KEY,name TEXT,phone TEXT,email TEXT,role TEXT,salary DOUBLE PRECISION,visits INTEGER,calls INTEGER,properties INTEGER,deals INTEGER,expense DOUBLE PRECISION,status TEXT,notes TEXT,created TEXT)""",
"""CREATE TABLE IF NOT EXISTS ledger(id BIGSERIAL PRIMARY KEY,dt TEXT,etype TEXT,category TEXT,source TEXT,amount DOUBLE PRECISION,ref TEXT,notes TEXT,created TEXT)""",
"""CREATE TABLE IF NOT EXISTS rent(id BIGSERIAL PRIMARY KEY,property_code TEXT,tenant TEXT,tenant_phone TEXT,owner TEXT,monthly_rent DOUBLE PRECISION,security DOUBLE PRECISION,due_day INTEGER,start_date TEXT,agreement_end TEXT,last_paid TEXT,status TEXT,notes TEXT,created TEXT)""",
"""CREATE TABLE IF NOT EXISTS projects(id BIGSERIAL PRIMARY KEY,name TEXT,ptype TEXT,client TEXT,phone TEXT,location TEXT,contract DOUBLE PRECISION,spent DOUBLE PRECISION,progress INTEGER,status TEXT,start_date TEXT,end_date TEXT,notes TEXT,created TEXT)""",
"""CREATE TABLE IF NOT EXISTS maintenance(id BIGSERIAL PRIMARY KEY,title TEXT,client TEXT,phone TEXT,location TEXT,category TEXT,priority TEXT,assigned TEXT,status TEXT,estimate DOUBLE PRECISION,spent DOUBLE PRECISION,notes TEXT,created TEXT)""",
"""CREATE TABLE IF NOT EXISTS mobile_users(id BIGSERIAL PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT,name TEXT,role TEXT,active INTEGER DEFAULT 1,created TEXT)""",
"""CREATE TABLE IF NOT EXISTS mobile_tokens(token TEXT PRIMARY KEY,user_id BIGINT,created TEXT)""",
"""CREATE TABLE IF NOT EXISTS staff_messages(id BIGSERIAL PRIMARY KEY,sender TEXT,recipient TEXT,message TEXT,created TEXT,read_at TEXT)""",
"""CREATE TABLE IF NOT EXISTS client_forms(id BIGSERIAL PRIMARY KEY,token TEXT UNIQUE,created_by TEXT,created TEXT,used INTEGER DEFAULT 0)"""
]

def db():
    if not DATABASE_URL: raise RuntimeError("DATABASE_URL is not configured")
    return psycopg2.connect(DATABASE_URL,cursor_factory=RealDictCursor)

def init_db():
    if not DATABASE_URL:return
    c=db();q=c.cursor()
    for s in SCHEMA:q.execute(s)
    for t in TABLES:
        q.execute(f"ALTER TABLE {t} ADD COLUMN IF NOT EXISTS created_by TEXT")
        q.execute(f"ALTER TABLE {t} ADD COLUMN IF NOT EXISTS updated_by TEXT")
    q.execute("""CREATE TABLE IF NOT EXISTS audit_log(
        id BIGSERIAL PRIMARY KEY,user_id BIGINT,username TEXT,user_name TEXT,action TEXT,module TEXT,
        record_id BIGINT,details TEXT,created TEXT)""")
    q.execute("SELECT id FROM mobile_users LIMIT 1")
    if not q.fetchone():
        q.execute("INSERT INTO mobile_users(username,password_hash,name,role,active,created) VALUES(%s,%s,%s,%s,1,%s)",
                  ("admin",generate_password_hash(ADMIN_PASSWORD),"Deewaryn Admin","Administrator",datetime.now().strftime("%Y-%m-%d %H:%M")))
    c.commit();c.close()

def query(sql,p=(),one=False):
    c=db();q=c.cursor();q.execute(sql,p);r=q.fetchone() if one else q.fetchall();c.close();return r

def execute(sql,p=(),return_id=False):
    c=db();q=c.cursor()
    if return_id: sql+=" RETURNING id"
    q.execute(sql,p);rid=q.fetchone()["id"] if return_id else None;c.commit();c.close();return rid

def auth(fn):
    @wraps(fn)
    def w(*a,**k):
        t=request.headers.get("Authorization","").replace("Bearer ","").strip()
        if not t:return jsonify(error="Unauthorized"),401
        r=query("""SELECT u.* FROM mobile_tokens t JOIN mobile_users u ON u.id=t.user_id
                   WHERE t.token=%s AND u.active=1""",(t,),True)
        if not r:return jsonify(error="Unauthorized"),401
        request.user=r
        return fn(*a,**k)
    return w

@app.get("/api/mobile/ping")
def ping():
    try:
        if DATABASE_URL:
            query("SELECT 1",(),True)
        return jsonify(ok=True,name="Deewaryn Enterprise Cloud",cloud=True)
    except Exception as e:return jsonify(ok=False,error=str(e)),500

@app.post("/api/mobile/login")
def login():
    x=request.get_json(silent=True) or {}
    r=query("SELECT * FROM mobile_users WHERE username=%s AND active=1",(x.get("username",""),),True)
    if not r or not check_password_hash(r["password_hash"],x.get("password","")):
        return jsonify(error="Wrong username or password"),401
    t=secrets.token_urlsafe(36)
    execute("INSERT INTO mobile_tokens(token,user_id,created) VALUES(%s,%s,%s)",(t,r["id"],datetime.now().isoformat()))
    return jsonify(token=t,user={"id":r["id"],"username":r["username"],"name":r["name"],"role":r["role"]})

@app.get("/api/mobile/dashboard")
@auth
def dashboard():
    month=datetime.now().strftime("%Y-%m")
    def scalar(sql,p=()):
        r=query(sql,p,True);return list(r.values())[0] if r else 0
    inc=scalar("SELECT COALESCE(SUM(amount),0) FROM ledger WHERE etype='Income' AND dt LIKE %s",(month+"%",))
    exp=scalar("SELECT COALESCE(SUM(amount),0) FROM ledger WHERE etype='Expense' AND dt LIKE %s",(month+"%",))
    follow=query("""SELECT id,name,phone,followup,stage,location,budget FROM contacts
                    WHERE COALESCE(TRIM(followup),'')<>'' AND COALESCE(stage,'') NOT IN ('Closed','Lost')
                    ORDER BY followup LIMIT 8""")
    return jsonify(
        properties=scalar("SELECT COUNT(*) FROM properties"),
        available_properties=scalar("SELECT COUNT(*) FROM properties WHERE COALESCE(status,'Available')='Available'"),
        contacts=scalar("SELECT COUNT(*) FROM contacts WHERE COALESCE(stage,'') NOT IN ('Closed','Lost')"),
        pending_clients=scalar("SELECT COUNT(*) FROM contacts WHERE COALESCE(stage,'New') IN ('New','Follow-up','Visit','Negotiation')"),
        done_clients=scalar("SELECT COUNT(*) FROM contacts WHERE COALESCE(stage,'')='Closed'"),
        open_deals=scalar("SELECT COUNT(*) FROM deals WHERE COALESCE(stage,'') NOT IN ('Closed Won','Closed Lost')"),
        won_deals=scalar("SELECT COUNT(*) FROM deals WHERE COALESCE(stage,'')='Closed Won'"),
        commission=scalar("SELECT COALESCE(SUM(commission),0) FROM deals WHERE COALESCE(stage,'')<>'Closed Lost'"),
        income=inc,expense=exp,profit=float(inc or 0)-float(exp or 0),
        tasks=scalar("SELECT COUNT(*) FROM tasks WHERE COALESCE(status,'')<>'Done'"),
        staff=scalar("SELECT COUNT(*) FROM employees WHERE COALESCE(status,'Active')='Active'"),
        rent_due=scalar("SELECT COUNT(*) FROM rent WHERE COALESCE(status,'')='Due'"),
        followups=follow)

@app.route("/api/mobile/<table>",methods=["GET","POST"])
@auth
def table_api(table):
    if table not in TABLES:return jsonify(error="Unknown module"),404
    fields=TABLES[table]
    if request.method=="GET":
        s=(request.args.get("q") or "").strip()
        if s:
            where=" OR ".join([f"CAST({f} AS TEXT) ILIKE %s" for f in fields])
            data=query(f"SELECT * FROM {table} WHERE {where} ORDER BY id DESC LIMIT 300",tuple(["%"+s+"%"]*len(fields)))
        else:data=query(f"SELECT * FROM {table} ORDER BY id DESC LIMIT 300")
        return jsonify(data)
    x=request.get_json(silent=True) or {}
    keys=[f for f in fields if f in x]
    if not keys:return jsonify(error="No data"),400
    vals=[]
    numeric={"price","beds","baths","budget","deal_value","commission","salary","visits","calls","properties","deals","expense","amount","monthly_rent","security","due_day","contract","spent","progress","estimate"}
    for k in keys:
        v=x.get(k)
        if k in numeric:
            try:v=float(v) if str(v).strip() else 0
            except:v=0
        vals.append(v)
    actor=request.user["name"] or request.user["username"]
    sql=f"INSERT INTO {table}({','.join(keys)},created,created_by) VALUES({','.join(['%s']*len(keys))},%s,%s)"
    rid=execute(sql,tuple(vals+[datetime.now().strftime("%Y-%m-%d %H:%M"),actor]),True)
    execute("""INSERT INTO audit_log(user_id,username,user_name,action,module,record_id,details,created)
               VALUES(%s,%s,%s,'CREATE',%s,%s,%s,%s)""",
            (request.user["id"],request.user["username"],actor,table,rid,"New record",
             datetime.now().strftime("%Y-%m-%d %H:%M")))
    return jsonify(ok=True,id=rid,created_by=actor)

@app.patch("/api/mobile/<table>/<int:row_id>")
@auth
def table_update(table,row_id):
    if table not in TABLES:return jsonify(error="Unknown module"),404
    x=request.get_json(silent=True) or {}
    fields=TABLES[table]
    keys=[k for k in fields if k in x]
    if not keys:return jsonify(error="No fields to update"),400
    numeric={"price","beds","baths","budget","deal_value","commission","salary","visits","calls","properties","deals","expense","amount","monthly_rent","security","due_day","contract","spent","progress","estimate"}
    vals=[]
    for k in keys:
        v=x.get(k)
        if k in numeric:
            try:v=float(v) if str(v).strip() else 0
            except:v=0
        vals.append(v)
    actor=request.user["name"] or request.user["username"]
    sets=",".join([f"{k}=%s" for k in keys])
    execute(f"UPDATE {table} SET {sets},updated_by=%s WHERE id=%s",tuple(vals+[actor,row_id]))
    execute("""INSERT INTO audit_log(user_id,username,user_name,action,module,record_id,details,created)
               VALUES(%s,%s,%s,'UPDATE',%s,%s,%s,%s)""",
            (request.user["id"],request.user["username"],actor,table,row_id,", ".join(keys),
             datetime.now().strftime("%Y-%m-%d %H:%M")))
    return jsonify(ok=True,id=row_id,updated_by=actor)

@app.delete("/api/mobile/<table>/<int:row_id>")
@auth
def table_delete(table,row_id):
    if table not in TABLES:return jsonify(error="Unknown module"),404
    if not admin_only():return jsonify(error="Only administrator can delete records"),403
    row=query(f"SELECT * FROM {table} WHERE id=%s",(row_id,),True)
    if not row:return jsonify(error="Record not found"),404
    actor=request.user["name"] or request.user["username"]
    execute(f"DELETE FROM {table} WHERE id=%s",(row_id,))
    execute("""INSERT INTO audit_log(user_id,username,user_name,action,module,record_id,details,created)
               VALUES(%s,%s,%s,'DELETE',%s,%s,%s,%s)""",
            (request.user["id"],request.user["username"],actor,table,row_id,
             str(dict(row))[:800],datetime.now().strftime("%Y-%m-%d %H:%M")))
    return jsonify(ok=True,id=row_id)

@app.get("/api/mobile/finance-summary")
@auth
def finance_summary():
    month=(request.args.get("month") or datetime.now().strftime("%Y-%m")).strip()
    income=query("""SELECT category,COALESCE(SUM(amount),0) amount FROM ledger
                    WHERE etype='Income' AND dt LIKE %s GROUP BY category ORDER BY amount DESC""",(month+"%",))
    expense=query("""SELECT category,COALESCE(SUM(amount),0) amount FROM ledger
                     WHERE etype='Expense' AND dt LIKE %s GROUP BY category ORDER BY amount DESC""",(month+"%",))
    source=query("""SELECT source,COALESCE(SUM(amount),0) amount FROM ledger
                    WHERE etype='Income' AND dt LIKE %s GROUP BY source ORDER BY amount DESC""",(month+"%",))
    def total(kind):
        r=query("SELECT COALESCE(SUM(amount),0) total FROM ledger WHERE etype=%s AND dt LIKE %s",(kind,month+"%"),True)
        return float(r["total"] or 0)
    inc=total("Income");exp=total("Expense")
    recent=query("SELECT * FROM ledger ORDER BY id DESC LIMIT 12")
    return jsonify(month=month,income=inc,expense=exp,profit=inc-exp,income_by_category=income,
                   expense_by_category=expense,income_by_source=source,recent=recent)

@app.route("/")
def home():return redirect("/mobile")


def admin_only():
    return str(request.user.get("role") or "").lower() in ("administrator","admin")

@app.route("/api/mobile/user-accounts",methods=["GET","POST"])
@auth
def user_accounts():
    if not admin_only():return jsonify(error="Administrator access required"),403
    if request.method=="GET":
        return jsonify(query("""SELECT id,username,name,role,active,created
                               FROM mobile_users ORDER BY id DESC"""))
    x=request.get_json(silent=True) or {}
    username=(x.get("username") or "").strip().lower()
    name=(x.get("name") or "").strip()
    role=(x.get("role") or "Staff").strip()
    password=x.get("password") or ""
    if len(username)<3:return jsonify(error="Username must be at least 3 characters"),400
    if not name:return jsonify(error="Staff name is required"),400
    if len(password)<6:return jsonify(error="Password must be at least 6 characters"),400
    if query("SELECT id FROM mobile_users WHERE username=%s",(username,),True):
        return jsonify(error="Username already exists"),400
    uid=execute("""INSERT INTO mobile_users(username,password_hash,name,role,active,created)
                   VALUES(%s,%s,%s,%s,1,%s)""",
                (username,generate_password_hash(password),name,role,datetime.now().strftime("%Y-%m-%d %H:%M")),True)
    return jsonify(ok=True,id=uid)

@app.patch("/api/mobile/user-accounts/<int:user_id>")
@auth
def update_user_account(user_id):
    if not admin_only():return jsonify(error="Administrator access required"),403
    x=request.get_json(silent=True) or {}
    allowed=[]
    vals=[]
    for k in ("name","role","active"):
        if k in x:
            allowed.append(k+"=%s"); vals.append(x[k])
    if x.get("password"):
        if len(x["password"])<6:return jsonify(error="Password must be at least 6 characters"),400
        allowed.append("password_hash=%s");vals.append(generate_password_hash(x["password"]))
    if not allowed:return jsonify(error="No changes"),400
    vals.append(user_id)
    execute("UPDATE mobile_users SET "+",".join(allowed)+" WHERE id=%s",tuple(vals))
    execute("DELETE FROM mobile_tokens WHERE user_id=%s",(user_id,))
    return jsonify(ok=True)

@app.delete("/api/mobile/user-accounts/<int:user_id>")
@auth
def delete_user_account(user_id):
    if not admin_only():return jsonify(error="Administrator access required"),403
    target=query("SELECT * FROM mobile_users WHERE id=%s",(user_id,),True)
    if not target:return jsonify(error="User not found"),404
    if target["username"]=="admin":return jsonify(error="Main admin account cannot be deleted"),400
    execute("DELETE FROM mobile_tokens WHERE user_id=%s",(user_id,))
    execute("DELETE FROM mobile_users WHERE id=%s",(user_id,))
    actor=request.user["name"] or request.user["username"]
    execute("""INSERT INTO audit_log(user_id,username,user_name,action,module,record_id,details,created)
               VALUES(%s,%s,%s,'DELETE','mobile_users',%s,%s,%s)""",
            (request.user["id"],request.user["username"],actor,user_id,
             "Deleted staff login: "+str(target.get("name") or target.get("username")),
             datetime.now().strftime("%Y-%m-%d %H:%M")))
    return jsonify(ok=True)

@app.get("/api/mobile/activity")
@auth
def activity():
    if admin_only():
        rows=query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100")
    else:
        rows=query("SELECT * FROM audit_log WHERE user_id=%s ORDER BY id DESC LIMIT 100",(request.user["id"],))
    return jsonify(rows)

@app.get("/api/mobile/staff")
@auth
def mobile_staff():
    rows=query("SELECT username,name,role,active FROM mobile_users ORDER BY name")
    return jsonify(rows)

@app.route("/api/mobile/messages",methods=["GET","POST"])
@auth
def mobile_messages():
    me=request.user["username"]
    if request.method=="GET":
        rows=query("""SELECT * FROM staff_messages
                      WHERE sender=%s OR recipient=%s OR recipient='ALL'
                      ORDER BY id DESC LIMIT 100""",(me,me))
        return jsonify(rows)
    x=request.get_json(silent=True) or {}
    recipient=(x.get("recipient") or "ALL").strip()
    message=(x.get("message") or "").strip()
    if not message:return jsonify(error="Message is required"),400
    rid=execute("INSERT INTO staff_messages(sender,recipient,message,created) VALUES(%s,%s,%s,%s)",
                (me,recipient,message,datetime.now().strftime("%Y-%m-%d %H:%M")),True)
    return jsonify(ok=True,id=rid)

@app.post("/api/mobile/client-form")
@auth
def create_client_form():
    token=secrets.token_urlsafe(18)
    execute("INSERT INTO client_forms(token,created_by,created,used) VALUES(%s,%s,%s,0)",
            (token,request.user["username"],datetime.now().strftime("%Y-%m-%d %H:%M")))
    return jsonify(ok=True,token=token,url=request.host_url.rstrip("/")+"/f/"+token)

@app.route("/f/<token>",methods=["GET","POST"])
@app.route("/client-form/<token>",methods=["GET","POST"])
def public_client_form(token):
    row=query("SELECT * FROM client_forms WHERE token=%s",(token,),True)
    if not row:return "Invalid or expired form link",404
    if request.method=="POST":
        f=request.form
        budget_raw="".join(ch for ch in (f.get("budget") or "") if ch.isdigit())
        budget=float(budget_raw or 0)
        purpose=(f.get("ctype") or "Buyer").strip()
        prop_type=(f.get("property_type") or "").strip()
        portion=(f.get("portion") or "").strip()
        area=(f.get("area") or "").strip()
        beds=(f.get("beds") or "").strip()
        location=(f.get("location") or "").strip()
        extra=(f.get("extra") or "").strip()
        parts=[]
        if prop_type: parts.append(prop_type)
        if portion: parts.append(portion)
        if area: parts.append(area)
        if beds: parts.append(beds+" Bed")
        if extra: parts.append(extra)
        requirement=" | ".join(parts)
        execute("""INSERT INTO contacts(name,phone,email,ctype,budget,location,requirement,source,stage,assigned,followup,notes,created,created_by)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,'Client Self Form','New','','','',%s,%s)""",
                (f.get("name",""),f.get("phone",""),f.get("email",""),purpose,budget,location,requirement,
                 datetime.now().strftime("%Y-%m-%d %H:%M"),row.get("created_by") or "Client Self Form"))
        execute("UPDATE client_forms SET used=1 WHERE token=%s",(token,))
        return """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
        <meta charset="utf-8"><title>Requirement Received | Deewaryn</title></head>
        <body style="margin:0;font-family:Arial;background:#0b2b1e;padding:24px">
        <div style="max-width:560px;margin:55px auto;background:white;padding:32px;border-radius:22px;text-align:center">
        <div style="font-weight:900;font-size:30px;color:#10251c">Dee<span style="color:#159b62">waryn</span></div>
        <h2 style="margin-top:24px;color:#159b62">Requirement received</h2>
        <p style="color:#65766d;line-height:1.6">Thank you. Our team will review suitable properties and contact you shortly.</p>
        <p style="font-size:12px;color:#829087">Official website: deewaryn.com</p>
        <a href="https://deewaryn.com" target="_blank" style="display:inline-block;margin-top:10px;background:#159b62;color:white;text-decoration:none;padding:12px 18px;border-radius:10px;font-weight:800">Visit Deewaryn.com</a>
        </div></body></html>"""
    ref=token[-6:].upper()
    locations=[
      "Bahria Town Phase 1","Bahria Town Phase 2","Bahria Town Phase 3","Bahria Town Phase 4",
      "Bahria Town Phase 5","Bahria Town Phase 6","Bahria Town Phase 7","Bahria Town Phase 8",
      "Bahria Safari Villas","DHA Phase 1 Islamabad","DHA Phase 2 Islamabad","DHA Phase 3 Islamabad",
      "DHA Phase 4 Islamabad","Askari 14","Askari 7","Askari 10","Chaklala Scheme 1","Chaklala Scheme 2",
      "Chaklala Scheme 3","Gulraiz Housing Scheme","Gulraiz 1","Gulraiz 2","Gulraiz 3","Media Town",
      "PWD Housing Scheme","Police Foundation","Soan Garden","Pakistan Town Phase 1","Pakistan Town Phase 2",
      "CBR Town Phase 1","CBR Town Phase 2","Jinnah Garden","Naval Anchorage","Ghauri Town Phase 4A",
      "Ghauri Town Phase 4B","Ghauri Town Phase 5","Ghauri Town Phase 7","Airport Housing Society",
      "Judicial Colony Rawalpindi","Adiala Road","Gulshan Abad","Caltex Road","Range Road","Misrial Road",
      "Westridge 1","Westridge 2","Westridge 3","Saddar Rawalpindi","Satellite Town Rawalpindi",
      "6th Road Rawalpindi","Shamsabad","Sadiqabad Rawalpindi","Commercial Market","Chandni Chowk",
      "Murree Road Rawalpindi","Khanna Pul","Korang Town","Taramri","Lehtrar Road","Park Road",
      "Bani Gala","Bhara Kahu","G-5 Islamabad","G-6 Islamabad","G-7 Islamabad","G-8 Islamabad",
      "G-9 Islamabad","G-10 Islamabad","G-11 Islamabad","G-12 Islamabad","G-13 Islamabad","G-14 Islamabad",
      "G-15 Islamabad","G-16 Islamabad","F-5 Islamabad","F-6 Islamabad","F-7 Islamabad","F-8 Islamabad",
      "F-10 Islamabad","F-11 Islamabad","F-12 Islamabad","F-13 Islamabad","F-14 Islamabad","F-15 Islamabad",
      "E-7 Islamabad","E-11 Islamabad","E-12 Islamabad","I-8 Islamabad","I-9 Islamabad","I-10 Islamabad",
      "I-11 Islamabad","I-12 Islamabad","H-13 Islamabad","H-15 Islamabad","I-14 Islamabad","I-15 Islamabad",
      "I-16 Islamabad","B-17 Islamabad","B-18 Islamabad","C-15 Islamabad","C-16 Islamabad","D-12 Islamabad",
      "D-13 Islamabad","D-17 Islamabad","Park View City Islamabad","Gulberg Greens","Gulberg Residencia",
      "Top City-1","Mumtaz City","Capital Smart City","Blue World City","Faisal Town","Faisal Hills",
      "MPCHS Multi Gardens B-17","E-16 Islamabad","E-17 Islamabad"
    ]
    options="".join(f'<option value="{x}"></option>' for x in locations)
    return f"""<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
    <meta charset="utf-8"><title>Property Requirement | Deewaryn</title>
    <style>
    *{{box-sizing:border-box}}body{{font-family:Arial;margin:0;background:#0b2b1e;color:#10251c;padding:14px}}
    .wrap{{max-width:700px;margin:16px auto}}.box{{background:#fff;border-radius:22px;overflow:hidden;box-shadow:0 25px 70px rgba(0,0,0,.22)}}
    .hero{{padding:22px 24px;background:#f7faf8;border-bottom:1px solid #e3ebe6}}.brand{{font-size:30px;font-weight:900}}.brand span{{color:#159b62}}
    .badge{{display:inline-block;background:#e9f6ef;color:#0f7c4d;padding:6px 10px;border-radius:999px;font-size:11px;font-weight:800;margin-top:8px}}
    .body{{padding:22px 24px}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}label{{display:block;font-size:12px;font-weight:800;color:#617168;margin-bottom:5px}}
    input,select,textarea{{width:100%;padding:11px 12px;border:1px solid #dce6e0;border-radius:10px;font-size:15px;background:#fff}}textarea{{min-height:92px;resize:vertical}}
    .full{{grid-column:1/-1}}button{{width:100%;padding:14px;border:0;border-radius:11px;background:#159b62;color:white;font-weight:900;font-size:16px;margin-top:15px}}
    .note{{margin-top:13px;font-size:11px;color:#718078;line-height:1.5;background:#f4f8f6;padding:11px;border-radius:10px}}
    .foot{{text-align:center;color:#d9e6df;font-size:11px;margin-top:12px}}@media(max-width:620px){{.grid{{grid-template-columns:1fr}}.full{{grid-column:auto}}}}
    </style></head><body><div class="wrap"><div class="box">
    <div class="hero"><div class="brand">Dee<span>waryn</span></div><div style="color:#66776f;margin-top:4px">Rawalpindi & Islamabad Real Estate</div><div class="badge">Official Requirement Form • {ref}</div></div>
    <div class="body"><h2 style="margin:0 0 4px">Find your property</h2><p style="margin:0 0 18px;color:#718078">Just select a few options. It takes less than a minute.</p>
    <form method="post" onsubmit="cleanBudget()"><div class="grid">
      <div><label>Name *</label><input name="name" required placeholder="Your name"></div>
      <div><label>Phone / WhatsApp *</label><input name="phone" required inputmode="numeric" pattern="[0-9+ ]*" placeholder="03xx xxxxxxx"></div>
      <div><label>Looking for</label><select name="ctype"><option>Buyer</option><option>Tenant</option><option>Investor</option></select></div>
      <div><label>Budget (numbers only)</label><input id="budget" name="budget" type="text" inputmode="numeric" pattern="[0-9]*" placeholder="35000000" oninput="this.value=this.value.replace(/[^0-9]/g,'')"></div>
      <div class="full"><label>Location</label><input name="location" list="locations" autocomplete="off" placeholder="Start typing e.g. Scheme 3, Bahria, G-13"><datalist id="locations">{options}</datalist></div>
      <div><label>Property type</label><select name="property_type"><option>House</option><option>Apartment</option><option>Plot</option><option>Commercial</option></select></div>
      <div><label>Portion</label><select name="portion"><option>Full House</option><option>Ground Portion</option><option>Upper Portion</option><option>Lower Portion</option><option>Not sure</option></select></div>
      <div><label>Area / Marla</label><select name="area"><option>3 Marla</option><option>4 Marla</option><option>5 Marla</option><option>6 Marla</option><option>7 Marla</option><option>8 Marla</option><option>10 Marla</option><option>12 Marla</option><option>1 Kanal</option><option>2 Kanal</option><option>Other</option></select></div>
      <div><label>Bedrooms</label><select name="beds"><option>1</option><option>2</option><option>3</option><option>4</option><option>5</option><option>6</option><option>7+</option></select></div>
      <div class="full"><label>Extra requirement (optional)</label><textarea name="extra" placeholder="Corner, park facing, basement, double unit, parking, new house, etc."></textarea></div>
    </div><button type="submit">Send My Requirement</button></form>
    <div class="note"><b>Privacy:</b> This form only collects your property requirement and contact details for Deewaryn. We never ask for passwords, PINs, OTPs or card details.</div>
    <div style="margin-top:14px;padding:14px;border:1px solid #dce8e1;border-radius:12px;background:#f8fbf9">
      <div style="font-weight:900">Want to know more about Deewaryn?</div>
      <div style="font-size:12px;color:#6d7d75;margin-top:4px">Visit our official website to explore our property and real-estate services.</div>
      <a href="https://deewaryn.com" target="_blank" style="display:inline-block;margin-top:10px;background:#102f22;color:white;text-decoration:none;padding:11px 14px;border-radius:9px;font-weight:800">Visit deewaryn.com</a>
    </div>
    </div></div><div class="foot">Official website: deewaryn.com • Secure HTTPS form</div></div>
    <script>function cleanBudget(){{var b=document.getElementById('budget');b.value=b.value.replace(/[^0-9]/g,'');}}</script>
    </body></html>"""

@app.get("/api/mobile/matches/<int:contact_id>")
@auth
def smart_matches(contact_id):
    cl=query("SELECT * FROM contacts WHERE id=%s",(contact_id,),True)
    if not cl:return jsonify(error="Client not found"),404
    props=query("SELECT * FROM properties WHERE COALESCE(status,'Available') NOT IN ('Sold','Rented') ORDER BY id DESC LIMIT 500")
    budget=float(cl.get("budget") or 0)
    loc=(cl.get("location") or "").lower().strip()
    req=(cl.get("requirement") or "").lower()
    ctype=(cl.get("ctype") or "").lower()
    want="rent" if "tenant" in ctype else "sale"
    scored=[]
    for p in props:
        score=0
        reasons=[]
        ploc=(p.get("location") or "").lower()
        ptype=(p.get("ptype") or "").lower()
        purpose=(p.get("purpose") or "").lower()
        price=float(p.get("price") or 0)
        if loc and (loc in ploc or ploc in loc):
            score+=45; reasons.append("location")
        if want and want in purpose:
            score+=20; reasons.append("purpose")
        if budget and price and price<=budget:
            score+=25; reasons.append("within budget")
        elif budget and price and price<=budget*1.1:
            score+=12; reasons.append("near budget")
        words=[w for w in req.replace(","," ").split() if len(w)>3]
        hits=sum(1 for w in words if w in (ploc+" "+ptype+" "+str(p.get("area") or "")+" "+str(p.get("beds") or "")))
        if hits:
            score+=min(20,hits*5); reasons.append("requirement")
        if score>0:
            x=dict(p);x["match_score"]=min(100,score);x["match_reasons"]=", ".join(reasons);scored.append(x)
    scored.sort(key=lambda x:x["match_score"],reverse=True)
    return jsonify(scored[:20])

@app.route("/mobile")
def mobile():
    return r"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Deewaryn Enterprise</title>
<style>
:root{--g:#159b62;--g2:#0c6e46;--gold:#d5a12a;--ink:#11251d;--muted:#718078;--bg:#f4f7f5;--line:#e0e8e3;--card:#fff;--nav:#0b2b1e}
*{box-sizing:border-box}body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--ink)}
button,input,select,textarea{font:inherit}.top{height:72px;background:linear-gradient(135deg,#08271a,#0e3a28);color:#fff;display:flex;align-items:center;padding:0 22px;position:sticky;top:0;z-index:20}
.brand{font-size:25px;font-weight:900}.brand span{color:var(--gold)}.sub{font-size:11px;opacity:.65}.top .grow{flex:1}.user{font-size:12px;opacity:.8}
.shell{display:grid;grid-template-columns:250px 1fr;min-height:calc(100vh - 72px)}.side{background:#fff;border-right:1px solid var(--line);padding:16px;position:sticky;top:72px;height:calc(100vh - 72px);overflow:auto}
.group{font-size:10px;color:#97a39d;text-transform:uppercase;font-weight:900;letter-spacing:1px;margin:16px 10px 7px}.nav{width:100%;border:0;background:transparent;padding:12px;border-radius:11px;text-align:left;font-weight:800;color:#53675c;cursor:pointer}.nav:hover,.nav.on{background:#eaf6ef;color:var(--g2)}
.main{padding:22px;min-width:0}.head{display:flex;gap:12px;align-items:center;margin-bottom:16px}.head h1{margin:0;font-size:28px}.muted{color:var(--muted);font-size:12px}.grow{flex:1}
.btn{border:0;border-radius:10px;padding:10px 13px;font-weight:800;cursor:pointer}.green{background:var(--g);color:#fff}.soft{background:#eaf6ef;color:var(--g2)}.gold{background:var(--gold);color:#171717}.dark{background:#173d2c;color:#fff}
.grid{display:grid;gap:13px}.kpis{grid-template-columns:repeat(4,minmax(0,1fr))}.card{background:#fff;border:1px solid var(--line);border-radius:17px;box-shadow:0 10px 28px rgba(17,37,29,.05)}
.kpi{padding:17px}.kpi small{color:var(--muted);font-weight:800;text-transform:uppercase}.kpi b{display:block;font-size:26px;margin-top:7px}
.cols2{grid-template-columns:1.3fr .7fr}.section{padding:17px}.section h3{margin:0 0 12px}.quick{display:grid;grid-template-columns:repeat(4,1fr);gap:9px}.quick button{padding:15px;border:1px solid var(--line);border-radius:13px;background:#fff;font-weight:800;cursor:pointer}
.tablebox{overflow:auto}.table{width:100%;border-collapse:collapse;min-width:900px}.table th,.table td{padding:12px;border-bottom:1px solid var(--line);text-align:left;font-size:12px}.table th{font-size:10px;text-transform:uppercase;color:#718078;background:#f8faf9}
.chip{display:inline-block;padding:5px 8px;border-radius:999px;background:#eef5f1;color:#4f655a;font-weight:800;font-size:10px}
.actions{display:flex;gap:6px;flex-wrap:wrap}.tiny{padding:7px 9px;font-size:11px}.search{width:min(420px,100%);padding:11px;border:1px solid var(--line);border-radius:10px}
.toolbar{display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap}.empty{padding:35px;text-align:center;color:var(--muted)}
.modal{position:fixed;inset:0;background:rgba(7,25,17,.58);display:none;align-items:center;justify-content:center;z-index:100;padding:18px}.modal.show{display:flex}.modalbox{width:min(760px,100%);max-height:90vh;overflow:auto;background:#fff;border-radius:18px}.mh{display:flex;align-items:center;padding:17px;border-bottom:1px solid var(--line)}.mb{padding:18px}
.form{display:grid;grid-template-columns:repeat(2,1fr);gap:11px}.field label{display:block;font-size:11px;font-weight:900;color:#65766d;margin-bottom:5px}.field input,.field select,.field textarea{width:100%;padding:11px;border:1px solid var(--line);border-radius:10px}.full{grid-column:1/-1}
.login{min-height:100vh;display:grid;place-items:center;background:linear-gradient(135deg,#08271a,#145438);padding:20px}.loginbox{width:min(430px,100%);background:#fff;border-radius:24px;padding:28px}.loginbox input{width:100%;padding:13px;margin:7px 0;border:1px solid var(--line);border-radius:10px}
.msglist{max-height:330px;overflow:auto}.msg{border-bottom:1px solid var(--line);padding:10px 0}.score{font-weight:900;color:var(--g2)}
.stagebar{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 14px}.stagebtn{border:1px solid var(--line);background:#fff;border-radius:999px;padding:8px 11px;font-size:11px;font-weight:800;cursor:pointer}
.stagebtn:hover{border-color:var(--g);color:var(--g2)}.finrow{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:14px}.miniList{display:grid;gap:8px}.miniItem{display:flex;align-items:center;gap:10px;padding:10px;border:1px solid var(--line);border-radius:11px}.bar{height:8px;background:#edf2ef;border-radius:999px;overflow:hidden}.bar i{display:block;height:100%;background:var(--g)}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}@keyframes pulseGlow{0%,100%{box-shadow:0 12px 28px rgba(17,37,29,.06)}50%{box-shadow:0 18px 38px rgba(21,155,98,.14)}}@keyframes sheen{0%{transform:translateX(-120%)}100%{transform:translateX(180%)}}
.dashHero{position:relative;overflow:hidden;background:linear-gradient(135deg,#09291c 0%,#0c5034 62%,#117a4f 100%);color:white;border-radius:24px;padding:26px;box-shadow:0 22px 55px rgba(8,39,26,.18);animation:rise .45s ease both}
.dashHero:after{content:"";position:absolute;inset:-30% auto -30% -30%;width:35%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.09),transparent);transform:skewX(-20deg);animation:sheen 7s linear infinite}
.dashHero h1{margin:0;font-size:32px}.dashHero p{margin:7px 0 0;color:#d6e7df;max-width:760px;line-height:1.5}.heroActions{display:flex;gap:8px;flex-wrap:wrap;margin-top:18px}
.dashSection{margin-top:17px}.sectionTitle{display:flex;align-items:center;gap:9px;margin-bottom:10px}.sectionTitle h3{margin:0;font-size:15px}.sectionTitle span{font-size:10px;background:#eaf6ef;color:var(--g2);padding:5px 8px;border-radius:999px;font-weight:900}
.categoryGrid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.categoryCard{position:relative;overflow:hidden;background:white;border:1px solid var(--line);border-radius:18px;padding:18px;min-height:128px;cursor:pointer;transition:.22s;animation:rise .45s ease both}.categoryCard:hover{transform:translateY(-4px);border-color:#b8d8c7;box-shadow:0 18px 36px rgba(17,37,29,.10)}.categoryCard b{font-size:16px;display:block}.categoryCard small{display:block;color:var(--muted);margin-top:5px;line-height:1.4}.categoryCard strong{display:block;font-size:24px;margin-top:12px;color:var(--g2)}
.kpi{animation:rise .45s ease both}.kpi:hover{animation:pulseGlow 1.6s ease infinite}.aboutBox{background:linear-gradient(135deg,#fff,#f4faf6);border:1px solid #dce9e1;border-radius:20px;padding:20px}.aboutLogo{font-size:26px;font-weight:900}.aboutLogo span{color:var(--g)}.aboutTags{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}.aboutTag{background:#edf6f1;color:#345947;padding:7px 9px;border-radius:999px;font-size:11px;font-weight:800}
@media(max-width:1100px){.categoryGrid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:1000px){.shell{grid-template-columns:1fr}.side{position:fixed;left:0;right:0;bottom:0;top:auto;height:68px;display:flex;overflow-x:auto;z-index:30;padding:7px}.group{display:none}.nav{min-width:120px;text-align:center}.main{padding-bottom:85px}.kpis{grid-template-columns:repeat(2,1fr)}.cols2{grid-template-columns:1fr}}
@media(max-width:650px){.main{padding:14px}.quick{grid-template-columns:repeat(2,1fr)}.form{grid-template-columns:1fr}.full{grid-column:auto}.head h1{font-size:22px}}
</style></head><body><div id="app"></div><div id="modal" class="modal"></div>
<script>
let token=localStorage.getItem('dw_token')||'',user=null,view='dashboard';
try{user=JSON.parse(localStorage.getItem('dw_user')||'null')}catch(e){}
const esc=v=>String(v??'').replace(/[&<>"]/g,s=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[s]));
const money=v=>'PKR '+Number(v||0).toLocaleString();
async function api(p,o={}){let h={'Content-Type':'application/json',...(o.headers||{})};if(token)h.Authorization='Bearer '+token;let r=await fetch(p,{...o,headers:h}),d=await r.json().catch(()=>({}));if(r.status===401){logout();throw Error('Session expired')}if(!r.ok)throw Error(d.error||('Server '+r.status));return d}
function login(){app.innerHTML='<div class="login"><div class="loginbox"><h1 style="margin:0">Dee<span style="color:var(--g)">waryn</span></h1><p class="muted">Enterprise Staff Cloud</p><input id="u" value="admin" placeholder="Username"><input id="p" type="password" placeholder="Password"><button class="btn green" style="width:100%;margin-top:8px" onclick="doLogin()">Secure Sign In</button><div id="lm" class="muted" style="margin-top:9px"></div></div></div>'}
async function doLogin(){try{let d=await api('/api/mobile/login',{method:'POST',body:JSON.stringify({username:u.value,password:p.value})});token=d.token;user=d.user;localStorage.setItem('dw_token',token);localStorage.setItem('dw_user',JSON.stringify(user));view='dashboard';render()}catch(e){lm.textContent=e.message}}
function logout(){localStorage.clear();token='';user=null;login()}
const navGroups=[
 ['MAIN',[['dashboard','Dashboard'],['about','About Company']]],
 ['SALES & CLIENTS',[['crm','CRM / Clients'],['deals','Deals'],['clientform','Client Form']]],
 ['PROPERTY',[['properties','Properties'],['matching','Smart Match']]],
 ['TEAM',[['staff','Staff Performance'],['userids','Staff IDs'],['messages','Staff Messages'],['activity','Activity Log'],['tasks','Tasks']]],
 ['FINANCE',[['finance','Finance'],['rent','Rent']]],
 ['OPERATIONS',[['projects','Projects'],['maintenance','Maintenance']]]
];
function shell(body){
 let admin=['administrator','admin'].includes(String(user?.role||'').toLowerCase());
 return '<div class="top"><div><div class="brand">Dee<span>waryn</span></div><div class="sub">Enterprise Command Center</div></div><div class="grow"></div><div class="user">'+esc(user?.name||'')+' • '+esc(user?.role||'')+'</div><button class="btn soft" style="margin-left:12px" onclick="logout()">Logout</button></div><div class="shell"><aside class="side">'+navGroups.map(g=>'<div class="group">'+g[0]+'</div>'+g[1].filter(n=>admin||n[0]!=='userids').map(n=>'<button class="nav '+(view===n[0]?'on':'')+'" onclick="go(\''+n[0]+'\')">'+n[1]+'</button>').join('')).join('')+'</aside><main class="main">'+body+'</main></div>'
}
function go(v){view=v;render()}
async function dashboard(){
 let d=await api('/api/mobile/dashboard');
 let follow=(d.followups||[]).slice(0,6);
 const cats=[
  ['crm','Clients','CRM, follow-ups and requirements',d.pending_clients],
  ['properties','Properties','Sale, rent and inventory',d.available_properties],
  ['deals','Deals','Negotiations and closing pipeline',d.open_deals],
  ['staff','Staff','Performance and team activity',d.staff],
  ['finance','Finance','Office income, expense and profit',money(d.profit)],
  ['rent','Rent','Tenants, agreements and dues',d.rent_due],
  ['projects','Projects','Construction and renovation work','Open'],
  ['maintenance','Maintenance','Maintenance jobs and estimates','Jobs']
 ];
 return '<div class="dashHero"><div class="muted" style="color:#cde2d7;font-weight:800">DEEWARYN ENTERPRISE</div><h1>Welcome, '+esc(user?.name||'Admin')+'</h1><p>Your complete real-estate command center for Rawalpindi & Islamabad — clients, property inventory, staff, finance, rent, projects and maintenance managed separately in one secure cloud system.</p><div class="heroActions"><button class="btn gold" onclick="go(\'clientform\')">Send Client Form</button><button class="btn soft" onclick="go(\'properties\')">Add / View Property</button><button class="btn dark" onclick="go(\'crm\')">Open CRM</button></div></div>'+
 '<div class="dashSection"><div class="sectionTitle"><h3>Business Categories</h3><span>SEPARATE MODULES</span></div><div class="categoryGrid">'+cats.map((x,i)=>'<div class="categoryCard" style="animation-delay:'+(i*45)+'ms" onclick="go(\''+x[0]+'\')"><b>'+x[1]+'</b><small>'+x[2]+'</small><strong>'+x[3]+'</strong></div>').join('')+'</div></div>'+
 '<div class="dashSection"><div class="sectionTitle"><h3>Key Performance</h3><span>LIVE</span></div><div class="grid kpis">'+[
 ['Available Properties',d.available_properties],['Pending Clients',d.pending_clients],['Open Deals',d.open_deals],['Won Deals',d.won_deals],
 ['Monthly Income',money(d.income)],['Monthly Expense',money(d.expense)],['Net Profit',money(d.profit)],['Open Tasks',d.tasks]
 ].map((x,i)=>'<div class="card kpi" style="animation-delay:'+(i*35)+'ms"><small>'+x[0]+'</small><b>'+x[1]+'</b></div>').join('')+'</div></div>'+
 '<div class="grid cols2 dashSection"><div class="card section"><div class="sectionTitle"><h3>Priority Follow-ups</h3><span>CLIENTS</span></div>'+(follow.length?follow.map(x=>'<div class="miniItem"><div class="grow"><b>'+esc(x.name)+'</b><div class="muted">'+esc(x.location||'')+' • '+esc(x.followup||'')+'</div></div><button class="btn soft tiny" onclick="go(\'crm\')">Open</button></div>').join(''):'<div class="empty">No pending follow-ups.</div>')+'</div>'+
 '<div class="aboutBox"><div class="aboutLogo">Dee<span>waryn</span></div><div style="font-weight:900;margin-top:6px">Real Estate & Property Services</div><p class="muted" style="line-height:1.6">Deewaryn manages property sales, rentals, property management, construction, renovation and maintenance across Rawalpindi & Islamabad.</p><div class="aboutTags"><span class="aboutTag">Sales</span><span class="aboutTag">Rentals</span><span class="aboutTag">Property Management</span><span class="aboutTag">Construction</span><span class="aboutTag">Maintenance</span></div><button class="btn green" style="margin-top:14px" onclick="go(\'about\')">About Company</button></div></div>';
}
const cfg={
 crm:{api:'contacts',title:'CRM / Clients',primary:'name',cols:['name','phone','ctype','budget','location','stage','assigned','followup']},
 deals:{api:'deals',title:'Deals Pipeline',primary:'title',cols:['title','client','property_code','stage','deal_value','commission','assigned','next_action']},
 properties:{api:'properties',title:'Property Inventory',primary:'code',cols:['code','purpose','ptype','location','area','price','beds','status','owner','phone']},
 tasks:{api:'tasks',title:'Team Tasks',primary:'title',cols:['title','assigned','due','priority','status','related_to']},
 finance:{api:'ledger',title:'Finance Center',primary:'category',cols:['dt','etype','category','source','amount','ref']},
 rent:{api:'rent',title:'Rent Management',primary:'tenant',cols:['property_code','tenant','tenant_phone','monthly_rent','due_day','agreement_end','status']},
 projects:{api:'projects',title:'Projects',primary:'name',cols:['name','ptype','client','location','contract','spent','progress','status']},
 maintenance:{api:'maintenance',title:'Maintenance',primary:'title',cols:['title','client','phone','location','category','priority','assigned','status','estimate','spent']},
 staff:{api:'employees',title:'Staff Management',primary:'name',cols:['name','role','phone','salary','visits','calls','properties','deals','expense','status']}
};
const fields={
 contacts:[['name','Client Name'],['phone','Phone'],['email','Email'],['ctype','Client Type'],['budget','Budget','number'],['location','Location'],['requirement','Requirement','textarea'],['source','Source'],['stage','Stage'],['assigned','Assigned'],['followup','Follow-up','date'],['notes','Notes','textarea']],
 properties:[
 ['code','Property Code'],
 ['purpose','Purpose','select',['Sale','Rent']],
 ['ptype','Property Type','select',['Full House','Ground Portion','Upper Portion','Lower Portion','Apartment','Plot','Commercial','Office','Shop','Farm House']],
 ['location','Location','location'],
 ['area','Area','select',['2.5 Marla','3 Marla','4 Marla','5 Marla','6 Marla','7 Marla','8 Marla','10 Marla','12 Marla','14 Marla','1 Kanal','2 Kanal','Other']],
 ['price','Price','number'],
 ['beds','Beds','select',['1','2','3','4','5','6','7','8','9','10+']],
 ['baths','Baths','select',['1','2','3','4','5','6','7','8','9','10+']],
 ['owner','Owner'],
 ['phone','Owner Phone','tel'],
 ['status','Status','select',['Available','Reserved','Sold','Rented','Hold']],
 ['notes','Property Notes','textarea']
],
 deals:[['title','Deal Title'],['client','Client'],['property_code','Property Code'],['stage','Stage'],['deal_value','Deal Value','number'],['commission','Commission','number'],['assigned','Assigned'],['next_action','Next Action'],['notes','Notes','textarea']],
 tasks:[['title','Task'],['related_to','Related To'],['due','Due','date'],['priority','Priority'],['status','Status'],['assigned','Assigned'],['notes','Notes','textarea']],
 employees:[['name','Employee'],['phone','Phone'],['email','Email'],['role','Role'],['salary','Salary','number'],['visits','Visits','number'],['calls','Calls','number'],['properties','Properties Found','number'],['deals','Deals Closed','number'],['expense','Expense','number'],['status','Status'],['notes','Notes','textarea']],
 ledger:[['dt','Date','date'],['etype','Type'],['category','Category'],['source','Source'],['amount','Amount','number'],['ref','Reference'],['notes','Notes','textarea']],
 rent:[['property_code','Property Code'],['tenant','Tenant'],['tenant_phone','Tenant Phone'],['owner','Owner'],['monthly_rent','Monthly Rent','number'],['security','Security','number'],['due_day','Due Day','number'],['start_date','Start','date'],['agreement_end','Agreement End','date'],['last_paid','Last Paid','date'],['status','Status'],['notes','Notes','textarea']],
 projects:[['name','Project'],['ptype','Type'],['client','Client'],['phone','Phone'],['location','Location'],['contract','Contract','number'],['spent','Spent','number'],['progress','Progress %','number'],['status','Status'],['start_date','Start','date'],['end_date','End','date'],['notes','Notes','textarea']],
 maintenance:[['title','Job'],['client','Client'],['phone','Phone'],['location','Location'],['category','Category'],['priority','Priority'],['assigned','Assigned'],['status','Status'],['estimate','Estimate','number'],['spent','Spent','number'],['notes','Notes','textarea']]
};
const propertyLocations=[
'Mumtaz Colony Rawalpindi','Mumtaz Market Rawalpindi','Chaklala Scheme 1','Chaklala Scheme 2','Chaklala Scheme 3','Scheme 3 Rawalpindi',
'Bostan Khan Road','Zeeshan Street Chaklala','Airport Housing Society','Gulzar-e-Quaid','Fazal Town Phase 1','Fazal Town Phase 2',
'Gulraiz 1','Gulraiz 2','Gulraiz 3','Gulraiz 4','Gulraiz 5','Media Town','PWD Housing Scheme','Police Foundation',
'Pakistan Town Phase 1','Pakistan Town Phase 2','Soan Garden','CBR Town Phase 1','CBR Town Phase 2','Jinnah Garden','Naval Anchorage',
'Korang Town','Khanna Pul','Ghauri Town Phase 4A','Ghauri Town Phase 4B','Ghauri Town Phase 5','Ghauri Town Phase 7','Ghauri Town Phase 8',
'Sadiqabad Rawalpindi','Shamsabad','Satellite Town Rawalpindi','Commercial Market','6th Road Rawalpindi','Chandni Chowk','Rehmanabad',
'Committee Chowk','Saddar Rawalpindi','Lal Kurti','Westridge 1','Westridge 2','Westridge 3','Westridge 4','Range Road','Misrial Road',
'Peshawar Road','Chur Chowk','Qasim Market','Tench Bhatta','Dhoke Syedan','Dhoke Chaudhrian','Dhoke Kashmirian','Dhoke Kala Khan',
'Dhoke Hassu','Pirwadhai','Asghar Mall Scheme','Arya Mohalla','Banni Rawalpindi','Kartarpura','Raja Bazar','College Road Rawalpindi',
'Tipu Road','Marir Hassan','Adiala Road','Munawar Colony','Gulshan Abad','Kehkashan Colony','Caltex Road','Dhamial Road','Girja Road',
'Morgah','Kotha Kalan','Dhok Juma','Askari 7','Askari 14','DHA Phase 1 Islamabad','DHA Phase 2 Islamabad','DHA Phase 3 Islamabad',
'DHA Phase 4 Islamabad','DHA Phase 5 Islamabad','Bahria Town Phase 1','Bahria Town Phase 2','Bahria Town Phase 3','Bahria Town Phase 4',
'Bahria Town Phase 5','Bahria Town Phase 6','Bahria Town Phase 7','Bahria Town Phase 8','Bahria Safari Villas','Bahria Garden City',
'Yousaf Colony Rawalpindi','Ayub Colony','Ali Town Rawalpindi','Defence Road Rawalpindi','Rawat',
'G-5 Islamabad','G-6 Islamabad','G-7 Islamabad','G-8 Islamabad','G-9 Islamabad','G-10 Islamabad','G-11 Islamabad','G-12 Islamabad',
'G-13 Islamabad','G-14 Islamabad','G-15 Islamabad','G-16 Islamabad','F-5 Islamabad','F-6 Islamabad','F-7 Islamabad','F-8 Islamabad',
'F-10 Islamabad','F-11 Islamabad','F-12 Islamabad','F-13 Islamabad','F-14 Islamabad','F-15 Islamabad','E-7 Islamabad','E-11 Islamabad',
'E-12 Islamabad','E-16 Islamabad','E-17 Islamabad','I-8 Islamabad','I-9 Islamabad','I-10 Islamabad','I-11 Islamabad','I-12 Islamabad',
'I-14 Islamabad','I-15 Islamabad','I-16 Islamabad','H-13 Islamabad','H-15 Islamabad','D-12 Islamabad','D-13 Islamabad','D-17 Islamabad',
'B-17 Islamabad','B-18 Islamabad','C-15 Islamabad','C-16 Islamabad','Faisal Town Islamabad','Faisal Hills','Top City-1','Mumtaz City',
'Capital Smart City','Blue World City','MPCHS Multi Gardens B-17','Gulberg Greens','Gulberg Residencia','Park View City Islamabad',
'Bani Gala','Bhara Kahu','Park Road Islamabad','Taramri','Lehtrar Road','Chatta Bakhtawar','Chak Shahzad','Kuri Road','Shahzad Town',
'NIH Colony','Margalla Town','Blue Area Islamabad'
];
function fieldControl(prefix,f,value=''){
 let [k,l,t='text',opts=[]]=f,v=esc(value??''),id=prefix+'_'+k;
 if(t==='textarea')return '<textarea id="'+id+'">'+v+'</textarea>';
 if(t==='select')return '<select id="'+id+'"><option value="">Select '+esc(l)+'</option>'+opts.map(o=>'<option value="'+esc(o)+'" '+(String(value??'')===String(o)?'selected':'')+'>'+esc(o)+'</option>').join('')+'</select>';
 if(t==='location')return '<input id="'+id+'" type="text" list="propertyLocationList" autocomplete="off" placeholder="Type area e.g. Mumtaz, Scheme 3, Bahria" value="'+v+'"><datalist id="propertyLocationList">'+propertyLocations.map(x=>'<option value="'+esc(x)+'"></option>').join('')+'</datalist>';
 if(t==='number')return '<input id="'+id+'" type="number" inputmode="numeric" min="0" value="'+v+'">';
 return '<input id="'+id+'" type="'+t+'" value="'+v+'">';
}
function fmt(k,v){if(v===null||v==='')return '—';if(['price','budget','deal_value','commission','salary','expense','amount','monthly_rent','security','contract','spent','estimate'].includes(k))return money(v);if(['status','stage','priority','purpose','etype'].includes(k))return '<span class="chip">'+esc(v)+'</span>';return esc(v)}
async function listPage(key){
 let cc=cfg[key],d=await api('/api/mobile/'+cc.api);
 let action='<button class="btn gold" onclick="openAdd(\''+cc.api+'\')">+ Add New</button>';
 let crmFilters=key==='crm'?'<div class="stagebar"><button class="stagebtn" onclick="crmFilter(\'all\')">All</button><button class="stagebtn" onclick="crmFilter(\'pending\')">Pending</button><button class="stagebtn" onclick="crmFilter(\'done\')">Done</button><button class="stagebtn" onclick="crmFilter(\'lost\')">Lost</button></div>':'';
 return '<div class="head"><div><h1>'+cc.title+'</h1><div class="muted">'+d.length+' records</div></div><div class="grow"></div>'+action+'</div>'+crmFilters+
 '<div class="toolbar"><input class="search" id="listSearch" placeholder="Search..." onkeydown="if(event.key===\'Enter\')searchPage(\''+key+'\',this.value)"></div>'+
 '<div class="card tablebox">'+tableHtml(key,d)+'</div>';
}
function tableHtml(key,d){
 let cc=cfg[key];
 if(!d.length)return '<div class="empty">No records yet.</div>';
 let isAdmin=['administrator','admin'].includes(String(user?.role||'').toLowerCase());
 return '<table class="table"><thead><tr>'+cc.cols.map(x=>'<th>'+x.replace(/_/g,' ')+'</th>').join('')+'<th>Entered By</th><th>Updated By</th><th>Actions</th></tr></thead><tbody>'+
 d.map(r=>'<tr data-stage="'+esc(r.stage||r.status||'')+'">'+cc.cols.map(x=>'<td>'+fmt(x,r[x])+'</td>').join('')+'<td><b>'+esc(r.created_by||'Legacy')+'</b></td><td>'+esc(r.updated_by||'—')+'</td><td><div class="actions">'+
 (key==='crm'?(r.phone?'<a class="btn green tiny" href="tel:'+esc(r.phone)+'">Call</a><a class="btn soft tiny" href="https://wa.me/'+esc(String(r.phone).replace(/[^0-9]/g,'').replace(/^0/,'92'))+'">WhatsApp</a>':'')+
 '<button class="btn dark tiny" onclick="openEdit(\'contacts\','+r.id+')">Edit</button><button class="btn soft tiny" onclick="setClientStage('+r.id+',\'Follow-up\')">Pending</button><button class="btn green tiny" onclick="setClientStage('+r.id+',\'Closed\')">Done</button><button class="btn gold tiny" onclick="showMatches('+r.id+',\''+esc(r.name).replace(/'/g,"&#39;")+'\')">Match</button>'
 :'<button class="btn dark tiny" onclick="openEdit(\''+cc.api+'\','+r.id+')">Edit</button>')+
 (isAdmin?'<button class="btn tiny" style="background:#fff0ee;color:#b42318" onclick="deleteRec(\''+cc.api+'\','+r.id+',\''+esc(String(r[cc.primary]||('Record #'+r.id))).replace(/'/g,"&#39;")+'\')">Delete</button>':'')+
 '</div></td></tr>').join('')+'</tbody></table>';
}
function crmFilter(mode){
 document.querySelectorAll('.table tbody tr').forEach(tr=>{
   let s=(tr.dataset.stage||'').toLowerCase();
   let show=mode==='all'||(mode==='pending'&&!['closed','lost'].includes(s))||(mode==='done'&&s==='closed')||(mode==='lost'&&s==='lost');
   tr.style.display=show?'':'none';
 });
}
async function setClientStage(id,stage){await api('/api/mobile/contacts/'+id,{method:'PATCH',body:JSON.stringify({stage})});render()}
async function deleteRec(apiName,id,label){
 if(!confirm('Delete '+label+' permanently?\n\nThis cannot be undone.'))return;
 try{await api('/api/mobile/'+apiName+'/'+id,{method:'DELETE'});render()}
 catch(e){alert(e.message)}
}
async function searchPage(key,q){let c=cfg[key],d=await api('/api/mobile/'+c.api+'?q='+encodeURIComponent(q));document.querySelector('.tablebox').innerHTML=d.length?'<table class="table"><tbody>'+d.map(r=>'<tr><td><b>'+esc(r[c.primary]||'')+'</b></td><td>'+esc(JSON.stringify(r).slice(0,180))+'</td></tr>').join('')+'</tbody></table>':'<div class="empty">No matches</div>'}
function openAdd(apiName){
 let fs=fields[apiName]||[];
 modal.innerHTML='<div class="modalbox"><div class="mh"><div><h2 style="margin:0">Add '+apiName.replace(/_/g,' ')+'</h2>'+(apiName==='properties'?'<div class="muted">Purpose, type, location, area and property details</div>':'')+'</div><div class="grow"></div><button class="btn soft" onclick="closeM()">Close</button></div><div class="mb"><div class="form">'+
 fs.map(f=>'<div class="field '+(f[2]==='textarea'||f[2]==='location'?'full':'')+'"><label>'+f[1]+'</label>'+fieldControl('f',f,'')+'</div>').join('')+
 '</div><div style="text-align:right;margin-top:14px"><button class="btn green" onclick="saveRec(\''+apiName+'\')">Save</button></div></div></div>';
 modal.classList.add('show')
}
function closeM(){modal.classList.remove('show')}
async function openEdit(apiName,id){
 let rows=await api('/api/mobile/'+apiName),row=rows.find(x=>Number(x.id)===Number(id));if(!row)return alert('Record not found');
 let fs=fields[apiName]||[];
 modal.innerHTML='<div class="modalbox"><div class="mh"><h2 style="margin:0">Edit '+apiName.replace(/_/g,' ')+'</h2><div class="grow"></div><button class="btn soft" onclick="closeM()">Close</button></div><div class="mb"><div class="form">'+
 fs.map(f=>'<div class="field '+(f[2]==='textarea'||f[2]==='location'?'full':'')+'"><label>'+f[1]+'</label>'+fieldControl('e',f,row[f[0]]??'')+'</div>').join('')+
 '</div><div style="text-align:right;margin-top:14px"><button class="btn green" onclick="saveEdit(\''+apiName+'\','+id+')">Save Changes</button></div></div></div>';
 modal.classList.add('show')
}
async function saveEdit(apiName,id){
 let o={};(fields[apiName]||[]).forEach(f=>{let e=document.getElementById('e_'+f[0]);if(e)o[f[0]]=e.value});
 await api('/api/mobile/'+apiName+'/'+id,{method:'PATCH',body:JSON.stringify(o)});closeM();render()
}
async function saveRec(apiName){let o={};(fields[apiName]||[]).forEach(f=>{let e=document.getElementById('f_'+f[0]);if(e&&e.value!=='')o[f[0]]=e.value});await api('/api/mobile/'+apiName,{method:'POST',body:JSON.stringify(o)});closeM();render()}
async function userIdsPage(){
 let rows=await api('/api/mobile/user-accounts');
 return '<div class="head"><div><h1>Staff Login IDs</h1><div class="muted">Create and control a separate login for every staff member.</div></div><div class="grow"></div><button class="btn gold" onclick="openUserCreate()">+ Create Staff ID</button></div>'+
 '<div class="card tablebox">'+(rows.length?'<table class="table"><thead><tr><th>Name</th><th>Username</th><th>Role</th><th>Status</th><th>Created</th><th>Action</th></tr></thead><tbody>'+
 rows.map(x=>'<tr><td><b>'+esc(x.name)+'</b></td><td>'+esc(x.username)+'</td><td>'+esc(x.role)+'</td><td><span class="chip">'+(Number(x.active)?'Active':'Disabled')+'</span></td><td>'+esc(x.created||'')+'</td><td><div class="actions"><button class="btn soft tiny" onclick="resetUser('+x.id+',\''+esc(x.name).replace(/'/g,"&#39;")+'\')">Password</button>'+
 (x.username!=='admin'?'<button class="btn '+(Number(x.active)?'dark':'green')+' tiny" onclick="toggleUser('+x.id+','+(Number(x.active)?0:1)+')">'+(Number(x.active)?'Disable':'Enable')+'</button><button class="btn tiny" style="background:#fff0ee;color:#b42318" onclick="deleteUser('+x.id+',\''+esc(x.name).replace(/'/g,"&#39;")+'\')">Delete</button>':'')+
 '</div></td></tr>').join('')+'</tbody></table>':'<div class="empty">No staff IDs.</div>')+'</div>'
}
function openUserCreate(){
 modal.innerHTML='<div class="modalbox"><div class="mh"><h2 style="margin:0">Create Staff Login ID</h2><div class="grow"></div><button class="btn soft" onclick="closeM()">Close</button></div><div class="mb"><div class="form">'+
 '<div class="field"><label>Full Name</label><input id="un"></div><div class="field"><label>Username</label><input id="uu" autocomplete="off"></div>'+
 '<div class="field"><label>Role</label><select id="ur"><option>Agent</option><option>Staff</option><option>Manager</option></select></div>'+
 '<div class="field"><label>Temporary Password</label><input id="up" type="password" autocomplete="new-password"></div></div>'+
 '<div class="muted" style="margin-top:10px">Each entry made after login will automatically show this staff member\'s name.</div>'+
 '<div style="text-align:right;margin-top:14px"><button class="btn green" onclick="createUser()">Create Login</button></div></div></div>';modal.classList.add('show')
}
async function createUser(){
 try{await api('/api/mobile/user-accounts',{method:'POST',body:JSON.stringify({name:un.value,username:uu.value,role:ur.value,password:up.value})});closeM();render()}catch(e){alert(e.message)}
}
async function toggleUser(id,active){if(!confirm(active?'Enable this staff login?':'Disable this staff login?'))return;await api('/api/mobile/user-accounts/'+id,{method:'PATCH',body:JSON.stringify({active})});render()}
async function deleteUser(id,name){
 if(!confirm('Delete staff login for '+name+' permanently?\n\nPrevious entries will stay in the system with their name.'))return;
 try{await api('/api/mobile/user-accounts/'+id,{method:'DELETE'});render()}
 catch(e){alert(e.message)}
}
async function resetUser(id,name){let p=prompt('New password for '+name+' (minimum 6 characters):');if(!p)return;try{await api('/api/mobile/user-accounts/'+id,{method:'PATCH',body:JSON.stringify({password:p})});alert('Password changed. Staff must login again.')}catch(e){alert(e.message)}}
async function activityPage(){
 let rows=await api('/api/mobile/activity');
 return '<div class="head"><div><h1>Activity Log</h1><div class="muted">Who entered or edited what, and when.</div></div></div><div class="card tablebox">'+
 (rows.length?'<table class="table"><thead><tr><th>Staff</th><th>Action</th><th>Module</th><th>Record</th><th>Details</th><th>Date / Time</th></tr></thead><tbody>'+rows.map(x=>'<tr><td><b>'+esc(x.user_name||x.username)+'</b></td><td><span class="chip">'+esc(x.action)+'</span></td><td>'+esc(x.module)+'</td><td>#'+esc(x.record_id)+'</td><td>'+esc(x.details||'')+'</td><td>'+esc(x.created||'')+'</td></tr>').join('')+'</tbody></table>':'<div class="empty">No activity yet.</div>')+'</div>'
}

async function financeCenter(){
 let [s,rows]=await Promise.all([api('/api/mobile/finance-summary'),api('/api/mobile/ledger')]);
 let maxExp=Math.max(1,...(s.expense_by_category||[]).map(x=>Number(x.amount||0)));
 return '<div class="head"><div><h1>Office Finance Management</h1><div class="muted">Monthly income, expenses, profit and spending control</div></div><div class="grow"></div><button class="btn gold" onclick="openAdd(\'ledger\')">+ Add Transaction</button></div>'+
 '<div class="finrow"><div class="card kpi"><small>Income</small><b>'+money(s.income)+'</b></div><div class="card kpi"><small>Expense</small><b>'+money(s.expense)+'</b></div><div class="card kpi"><small>Net Profit</small><b>'+money(s.profit)+'</b></div></div>'+
 '<div class="grid cols2"><div class="card section"><h3>Expense Breakdown</h3><div class="miniList">'+((s.expense_by_category||[]).map(x=>'<div><div style="display:flex"><b class="grow">'+esc(x.category||'Other')+'</b><span>'+money(x.amount)+'</span></div><div class="bar" style="margin-top:6px"><i style="width:'+Math.max(4,Math.round(Number(x.amount||0)/maxExp*100))+'%"></i></div></div>').join('')||'<div class="empty">No expenses this month.</div>')+'</div></div>'+
 '<div class="card section"><h3>Income Sources</h3><div class="miniList">'+((s.income_by_source||[]).map(x=>'<div class="miniItem"><b class="grow">'+esc(x.source||'Other')+'</b><span>'+money(x.amount)+'</span></div>').join('')||'<div class="empty">No income this month.</div>')+'</div></div></div>'+
 '<div class="card tablebox" style="margin-top:14px">'+tableHtml('finance',rows)+'</div>';
}

async function aboutCompany(){
 return '<div class="head"><div><h1>About Deewaryn</h1><div class="muted">Company profile and service overview</div></div></div>'+
 '<div class="dashHero"><div class="aboutLogo" style="font-size:34px;color:white">Dee<span style="color:var(--gold)">waryn</span></div><h2 style="margin:12px 0 4px">Real Estate • Property Management • Construction</h2><p>Deewaryn is a Rawalpindi & Islamabad focused real-estate business built to manage property sales, rentals, client requirements, property management, construction, renovation and maintenance through one professional system.</p></div>'+
 '<div class="dashSection"><div class="categoryGrid">'+
 [['Sales & Purchase','Residential, plots, apartments and commercial property.'],['Rentals','Full houses, portions and commercial rentals.'],['Property Management','Tenant, rent, owner and property management.'],['Construction','New house construction and project management.'],['Renovation','Kitchen, washroom, wardrobe, ceiling and interior upgrades.'],['Maintenance','Electrical, plumbing, paint and property maintenance.'],['Marketing','Property videos, online listings and client outreach.'],['Service Area','Rawalpindi & Islamabad.']].map((x,i)=>'<div class="categoryCard" style="animation-delay:'+(i*45)+'ms"><b>'+x[0]+'</b><small>'+x[1]+'</small></div>').join('')+
 '</div></div>'+
 '<div class="card section dashSection"><h3>Company Mission</h3><p style="line-height:1.7;color:#52655b">Keep every client, property, deal, staff activity and office expense organized in one place so the Deewaryn team can respond faster, follow up properly and grow with a professional process.</p></div>';
}

async function clientForm(){return '<div class="head"><div><h1>Client Requirement Link</h1><div class="muted">Generate an official branded form link and send it to a client.</div></div></div><div class="grid cols2"><div class="card section"><h3>Create secure link</h3><p class="muted">Client fills name, WhatsApp, budget, location and requirement. Submission automatically enters CRM as a New lead.</p><button class="btn green" onclick="makeClientForm()">Generate Official Form Link</button><div id="formResult" style="margin-top:14px"></div></div><div class="card section"><h3>Why clients can trust it</h3><div class="miniList"><div class="miniItem">Official Deewaryn branding</div><div class="miniItem">Secure HTTPS page</div><div class="miniItem">No password, PIN or card details requested</div><div class="miniItem">Unique reference number on every form</div></div></div></div>'}
async function makeClientForm(){let d=await api('/api/mobile/client-form',{method:'POST',body:'{}'});formResult.innerHTML='<input class="search" style="width:100%" value="'+esc(d.url)+'" readonly><div style="margin-top:9px"><button class="btn soft" onclick="navigator.clipboard.writeText(\''+esc(d.url)+'\')">Copy Link</button> <a class="btn green" target="_blank" href="'+esc(d.url)+'">Open Form</a></div>'}
async function messages(){let [m,s]=await Promise.all([api('/api/mobile/messages'),api('/api/mobile/staff')]);return '<div class="head"><div><h1>Staff Messages</h1><div class="muted">Internal team communication</div></div></div><div class="grid cols2"><div class="card section"><h3>Send Message</h3><select id="mr" class="search" style="width:100%"><option value="ALL">All Staff</option>'+s.map(x=>'<option value="'+esc(x.username)+'">'+esc(x.name)+' — '+esc(x.role)+'</option>').join('')+'</select><textarea id="mm" class="search" style="width:100%;height:110px;margin-top:9px" placeholder="Message..."></textarea><button class="btn green" style="margin-top:8px" onclick="sendMsg()">Send</button></div><div class="card section"><h3>Recent Messages</h3><div class="msglist">'+(m.map(x=>'<div class="msg"><b>'+esc(x.sender)+'</b> → '+esc(x.recipient)+'<div>'+esc(x.message)+'</div><div class="muted">'+esc(x.created)+'</div></div>').join('')||'<div class="empty">No messages</div>')+'</div></div></div>'}
async function sendMsg(){await api('/api/mobile/messages',{method:'POST',body:JSON.stringify({recipient:mr.value,message:mm.value})});render()}
async function matching(){let cs=await api('/api/mobile/contacts');return '<div class="head"><div><h1>Smart Property Match</h1><div class="muted">Select a client to rank matching properties automatically</div></div></div><div class="card section">'+(cs.length?cs.map(x=>'<div style="padding:10px 0;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px"><div class="grow"><b>'+esc(x.name)+'</b><div class="muted">'+esc(x.location)+' • '+money(x.budget)+'</div></div><button class="btn gold" onclick="showMatches('+x.id+',\''+esc(x.name).replace(/'/g,"&#39;")+'\')">Find Matches</button></div>').join(''):'<div class="empty">Add clients first.</div>')+'</div>'}
async function showMatches(id,name){let d=await api('/api/mobile/matches/'+id);modal.innerHTML='<div class="modalbox"><div class="mh"><h2 style="margin:0">Matches for '+name+'</h2><div class="grow"></div><button class="btn soft" onclick="closeM()">Close</button></div><div class="mb">'+(d.length?d.map(x=>'<div class="card section" style="margin-bottom:10px"><div style="display:flex;gap:10px"><div class="grow"><b>'+esc(x.code||x.ptype)+'</b><div class="muted">'+esc(x.location)+' • '+esc(x.area)+' • '+money(x.price)+'</div><div class="muted">'+esc(x.match_reasons)+'</div></div><div class="score">'+x.match_score+'%</div></div></div>').join(''):'<div class="empty">No suitable properties found.</div>')+'</div></div>';modal.classList.add('show')}
async function render(){if(!token||!user){login();return}app.innerHTML=shell('<div class="card section">Loading...</div>');try{let body;if(view==='dashboard')body=await dashboard();else if(view==='clientform')body=await clientForm();else if(view==='messages')body=await messages();else if(view==='matching')body=await matching();else if(view==='about')body=await aboutCompany();else if(view==='finance')body=await financeCenter();else if(view==='userids')body=await userIdsPage();else if(view==='activity')body=await activityPage();else body=await listPage(view);app.innerHTML=shell(body)}catch(e){app.innerHTML=shell('<div class="card section"><h3>Error</h3><p>'+esc(e.message)+'</p></div>')}}
render();
</script></body></html>"""

try:init_db()
except Exception as e:print("DB init deferred:",e)
