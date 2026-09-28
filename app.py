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
    follow=query("""SELECT name,phone,followup,stage FROM contacts
                    WHERE COALESCE(TRIM(followup),'')<>'' ORDER BY followup LIMIT 10""")
    return jsonify(
        properties=scalar("SELECT COUNT(*) FROM properties"),
        contacts=scalar("SELECT COUNT(*) FROM contacts WHERE COALESCE(stage,'') NOT IN ('Closed','Lost')"),
        open_deals=scalar("SELECT COUNT(*) FROM deals WHERE COALESCE(stage,'') NOT IN ('Closed Won','Closed Lost')"),
        commission=scalar("SELECT COALESCE(SUM(commission),0) FROM deals WHERE COALESCE(stage,'')<>'Closed Lost'"),
        income=inc,expense=exp,profit=float(inc or 0)-float(exp or 0),
        tasks=scalar("SELECT COUNT(*) FROM tasks WHERE COALESCE(status,'')<>'Done'"),
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
    sql=f"INSERT INTO {table}({','.join(keys)},created) VALUES({','.join(['%s']*len(keys))},%s)"
    rid=execute(sql,tuple(vals+[datetime.now().strftime("%Y-%m-%d %H:%M")]),True)
    return jsonify(ok=True,id=rid)

@app.route("/")
def home():return redirect("/mobile")


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
    return jsonify(ok=True,token=token,url=request.host_url.rstrip("/")+"/client-form/"+token)

@app.route("/client-form/<token>",methods=["GET","POST"])
def public_client_form(token):
    row=query("SELECT * FROM client_forms WHERE token=%s",(token,),True)
    if not row:return "Invalid or expired form link",404
    if request.method=="POST":
        f=request.form
        execute("""INSERT INTO contacts(name,phone,email,ctype,budget,location,requirement,source,stage,assigned,followup,notes,created)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,'Client Self Form','New','','','',%s)""",
                (f.get("name",""),f.get("phone",""),f.get("email",""),f.get("ctype","Buyer"),
                 float(f.get("budget") or 0),f.get("location",""),f.get("requirement",""),
                 datetime.now().strftime("%Y-%m-%d %H:%M")))
        execute("UPDATE client_forms SET used=1 WHERE token=%s",(token,))
        return """<!doctype html><html><body style="font-family:Arial;background:#f3f6f5;padding:30px">
        <div style="max-width:520px;margin:auto;background:white;padding:30px;border-radius:18px">
        <h2 style="color:#169b62">Thank you</h2><p>Your requirement has been received by Deewaryn.</p></div></body></html>"""
    return """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Deewaryn Client Requirement</title><style>
    body{font-family:Arial;background:#0c251b;margin:0;padding:20px}.box{max-width:620px;margin:30px auto;background:#fff;border-radius:20px;padding:24px}
    input,select,textarea{width:100%;box-sizing:border-box;padding:12px;margin:7px 0 14px;border:1px solid #dfe7e3;border-radius:10px}
    button{width:100%;padding:13px;border:0;border-radius:10px;background:#169b62;color:#fff;font-weight:800}
    </style></head><body><div class="box"><h1>Deewaryn</h1><p>Tell us what property you need. Our team will contact you.</p>
    <form method="post"><label>Name</label><input name="name" required><label>Phone</label><input name="phone" required>
    <label>Email</label><input name="email"><label>I am looking to</label><select name="ctype"><option>Buyer</option><option>Tenant</option><option>Investor</option></select>
    <label>Budget (PKR)</label><input name="budget" type="number"><label>Preferred Location</label><input name="location">
    <label>Requirement</label><textarea name="requirement" rows="5" placeholder="e.g. 10 marla house, 4 beds, Bahria Phase 4"></textarea>
    <button type="submit">Send Requirement</button></form></div></body></html>"""

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
 ['MAIN',[['dashboard','Dashboard']]],
 ['SALES & CLIENTS',[['crm','CRM / Clients'],['deals','Deals'],['clientform','Client Form']]],
 ['PROPERTY',[['properties','Properties'],['matching','Smart Match']]],
 ['TEAM',[['staff','Staff'],['messages','Staff Messages'],['tasks','Tasks']]],
 ['FINANCE',[['finance','Finance'],['rent','Rent']]],
 ['OPERATIONS',[['projects','Projects'],['maintenance','Maintenance']]]
];
function shell(body){return '<div class="top"><div><div class="brand">Dee<span>waryn</span></div><div class="sub">Enterprise Command Center</div></div><div class="grow"></div><div class="user">'+esc(user?.name||'')+' • '+esc(user?.role||'')+'</div><button class="btn soft" style="margin-left:12px" onclick="logout()">Logout</button></div><div class="shell"><aside class="side">'+navGroups.map(g=>'<div class="group">'+g[0]+'</div>'+g[1].map(n=>'<button class="nav '+(view===n[0]?'on':'')+'" onclick="go(\''+n[0]+'\')">'+n[1]+'</button>').join('')).join('')+'</aside><main class="main">'+body+'</main></div>'}
function go(v){view=v;render()}
async function dashboard(){let d=await api('/api/mobile/dashboard');return '<div class="head"><div><h1>Executive Dashboard</h1><div class="muted">Sales, staff, property and finance at a glance</div></div></div><div class="grid kpis">'+[['Properties',d.properties],['Active Clients',d.contacts],['Open Deals',d.open_deals],['Commission',money(d.commission)],['Income',money(d.income)],['Expense',money(d.expense)],['Profit',money(d.profit)],['Open Tasks',d.tasks]].map(x=>'<div class="card kpi"><small>'+x[0]+'</small><b>'+x[1]+'</b></div>').join('')+'</div><div class="grid cols2" style="margin-top:14px"><div class="card section"><h3>Quick Actions</h3><div class="quick"><button onclick="go(\'crm\')">+ Client</button><button onclick="go(\'properties\')">+ Property</button><button onclick="go(\'deals\')">+ Deal</button><button onclick="go(\'clientform\')">Send Client Form</button></div></div><div class="card section"><h3>Follow-ups</h3>'+((d.followups||[]).slice(0,5).map(x=>'<div style="padding:8px 0;border-bottom:1px solid var(--line)"><b>'+esc(x.name)+'</b><div class="muted">'+esc(x.stage)+' • '+esc(x.followup)+'</div></div>').join('')||'<div class="empty">No follow-ups</div>')+'</div></div>'}
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
 properties:[['code','Property Code'],['purpose','Purpose'],['ptype','Property Type'],['location','Location'],['area','Area'],['price','Price','number'],['beds','Beds','number'],['baths','Baths','number'],['owner','Owner'],['phone','Phone'],['status','Status'],['notes','Notes','textarea']],
 deals:[['title','Deal Title'],['client','Client'],['property_code','Property Code'],['stage','Stage'],['deal_value','Deal Value','number'],['commission','Commission','number'],['assigned','Assigned'],['next_action','Next Action'],['notes','Notes','textarea']],
 tasks:[['title','Task'],['related_to','Related To'],['due','Due','date'],['priority','Priority'],['status','Status'],['assigned','Assigned'],['notes','Notes','textarea']],
 employees:[['name','Employee'],['phone','Phone'],['email','Email'],['role','Role'],['salary','Salary','number'],['visits','Visits','number'],['calls','Calls','number'],['properties','Properties Found','number'],['deals','Deals Closed','number'],['expense','Expense','number'],['status','Status'],['notes','Notes','textarea']],
 ledger:[['dt','Date','date'],['etype','Type'],['category','Category'],['source','Source'],['amount','Amount','number'],['ref','Reference'],['notes','Notes','textarea']],
 rent:[['property_code','Property Code'],['tenant','Tenant'],['tenant_phone','Tenant Phone'],['owner','Owner'],['monthly_rent','Monthly Rent','number'],['security','Security','number'],['due_day','Due Day','number'],['start_date','Start','date'],['agreement_end','Agreement End','date'],['last_paid','Last Paid','date'],['status','Status'],['notes','Notes','textarea']],
 projects:[['name','Project'],['ptype','Type'],['client','Client'],['phone','Phone'],['location','Location'],['contract','Contract','number'],['spent','Spent','number'],['progress','Progress %','number'],['status','Status'],['start_date','Start','date'],['end_date','End','date'],['notes','Notes','textarea']],
 maintenance:[['title','Job'],['client','Client'],['phone','Phone'],['location','Location'],['category','Category'],['priority','Priority'],['assigned','Assigned'],['status','Status'],['estimate','Estimate','number'],['spent','Spent','number'],['notes','Notes','textarea']]
};
function fmt(k,v){if(v===null||v==='')return '—';if(['price','budget','deal_value','commission','salary','expense','amount','monthly_rent','security','contract','spent','estimate'].includes(k))return money(v);if(['status','stage','priority','purpose','etype'].includes(k))return '<span class="chip">'+esc(v)+'</span>';return esc(v)}
async function listPage(key){let c=cfg[key],d=await api('/api/mobile/'+c.api);let action='<button class="btn gold" onclick="openAdd(\''+c.api+'\')">+ Add New</button>';return '<div class="head"><div><h1>'+c.title+'</h1><div class="muted">'+d.length+' records</div></div><div class="grow"></div>'+action+'</div><div class="toolbar"><input class="search" placeholder="Search..." onkeydown="if(event.key===\'Enter\')searchPage(\''+key+'\',this.value)"></div><div class="card tablebox">'+(d.length?'<table class="table"><thead><tr>'+c.cols.map(x=>'<th>'+x.replace(/_/g,' ')+'</th>').join('')+(key==='crm'?'<th>Actions</th>':'')+'</tr></thead><tbody>'+d.map(r=>'<tr>'+c.cols.map(x=>'<td>'+fmt(x,r[x])+'</td>').join('')+(key==='crm'?'<td><div class="actions">'+(r.phone?'<a class="btn green tiny" href="tel:'+esc(r.phone)+'">Call</a><a class="btn soft tiny" href="https://wa.me/'+esc(String(r.phone).replace(/[^0-9]/g,'').replace(/^0/,'92'))+'">WhatsApp</a>':'')+'<button class="btn gold tiny" onclick="showMatches('+r.id+',\''+esc(r.name).replace(/'/g,"&#39;")+'\')">Match</button></div></td>':'')+'</tr>').join('')+'</tbody></table>':'<div class="empty">No records yet.</div>')+'</div>'}
async function searchPage(key,q){let c=cfg[key],d=await api('/api/mobile/'+c.api+'?q='+encodeURIComponent(q));document.querySelector('.tablebox').innerHTML=d.length?'<table class="table"><tbody>'+d.map(r=>'<tr><td><b>'+esc(r[c.primary]||'')+'</b></td><td>'+esc(JSON.stringify(r).slice(0,180))+'</td></tr>').join('')+'</tbody></table>':'<div class="empty">No matches</div>'}
function openAdd(apiName){let fs=fields[apiName]||[];modal.innerHTML='<div class="modalbox"><div class="mh"><h2 style="margin:0">Add '+apiName.replace(/_/g,' ')+'</h2><div class="grow"></div><button class="btn soft" onclick="closeM()">Close</button></div><div class="mb"><div class="form">'+fs.map(f=>{let [k,l,t='text']=f;return '<div class="field '+(t==='textarea'?'full':'')+'"><label>'+l+'</label>'+(t==='textarea'?'<textarea id="f_'+k+'"></textarea>':'<input id="f_'+k+'" type="'+t+'">')+'</div>'}).join('')+'</div><div style="text-align:right;margin-top:14px"><button class="btn green" onclick="saveRec(\''+apiName+'\')">Save</button></div></div></div>';modal.classList.add('show')}
function closeM(){modal.classList.remove('show')}
async function saveRec(apiName){let o={};(fields[apiName]||[]).forEach(f=>{let e=document.getElementById('f_'+f[0]);if(e&&e.value!=='')o[f[0]]=e.value});await api('/api/mobile/'+apiName,{method:'POST',body:JSON.stringify(o)});closeM();render()}
async function clientForm(){return '<div class="head"><div><h1>Client Self-Form</h1><div class="muted">Send a secure form to a client. They fill their own requirement.</div></div></div><div class="card section"><h3>Create new client form link</h3><p class="muted">The submitted requirement automatically enters CRM.</p><button class="btn green" onclick="makeClientForm()">Generate Link</button><div id="formResult" style="margin-top:14px"></div></div>'}
async function makeClientForm(){let d=await api('/api/mobile/client-form',{method:'POST',body:'{}'});formResult.innerHTML='<input class="search" style="width:100%" value="'+esc(d.url)+'" readonly><div style="margin-top:9px"><button class="btn soft" onclick="navigator.clipboard.writeText(\''+esc(d.url)+'\')">Copy Link</button> <a class="btn green" target="_blank" href="'+esc(d.url)+'">Open Form</a></div>'}
async function messages(){let [m,s]=await Promise.all([api('/api/mobile/messages'),api('/api/mobile/staff')]);return '<div class="head"><div><h1>Staff Messages</h1><div class="muted">Internal team communication</div></div></div><div class="grid cols2"><div class="card section"><h3>Send Message</h3><select id="mr" class="search" style="width:100%"><option value="ALL">All Staff</option>'+s.map(x=>'<option value="'+esc(x.username)+'">'+esc(x.name)+' — '+esc(x.role)+'</option>').join('')+'</select><textarea id="mm" class="search" style="width:100%;height:110px;margin-top:9px" placeholder="Message..."></textarea><button class="btn green" style="margin-top:8px" onclick="sendMsg()">Send</button></div><div class="card section"><h3>Recent Messages</h3><div class="msglist">'+(m.map(x=>'<div class="msg"><b>'+esc(x.sender)+'</b> → '+esc(x.recipient)+'<div>'+esc(x.message)+'</div><div class="muted">'+esc(x.created)+'</div></div>').join('')||'<div class="empty">No messages</div>')+'</div></div></div>'}
async function sendMsg(){await api('/api/mobile/messages',{method:'POST',body:JSON.stringify({recipient:mr.value,message:mm.value})});render()}
async function matching(){let cs=await api('/api/mobile/contacts');return '<div class="head"><div><h1>Smart Property Match</h1><div class="muted">Select a client to rank matching properties automatically</div></div></div><div class="card section">'+(cs.length?cs.map(x=>'<div style="padding:10px 0;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px"><div class="grow"><b>'+esc(x.name)+'</b><div class="muted">'+esc(x.location)+' • '+money(x.budget)+'</div></div><button class="btn gold" onclick="showMatches('+x.id+',\''+esc(x.name).replace(/'/g,"&#39;")+'\')">Find Matches</button></div>').join(''):'<div class="empty">Add clients first.</div>')+'</div>'}
async function showMatches(id,name){let d=await api('/api/mobile/matches/'+id);modal.innerHTML='<div class="modalbox"><div class="mh"><h2 style="margin:0">Matches for '+name+'</h2><div class="grow"></div><button class="btn soft" onclick="closeM()">Close</button></div><div class="mb">'+(d.length?d.map(x=>'<div class="card section" style="margin-bottom:10px"><div style="display:flex;gap:10px"><div class="grow"><b>'+esc(x.code||x.ptype)+'</b><div class="muted">'+esc(x.location)+' • '+esc(x.area)+' • '+money(x.price)+'</div><div class="muted">'+esc(x.match_reasons)+'</div></div><div class="score">'+x.match_score+'%</div></div></div>').join(''):'<div class="empty">No suitable properties found.</div>')+'</div></div>';modal.classList.add('show')}
async function render(){if(!token||!user){login();return}app.innerHTML=shell('<div class="card section">Loading...</div>');try{let body;if(view==='dashboard')body=await dashboard();else if(view==='clientform')body=await clientForm();else if(view==='messages')body=await messages();else if(view==='matching')body=await matching();else body=await listPage(view);app.innerHTML=shell(body)}catch(e){app.innerHTML=shell('<div class="card section"><h3>Error</h3><p>'+esc(e.message)+'</p></div>')}}
render();
</script></body></html>"""

try:init_db()
except Exception as e:print("DB init deferred:",e)
