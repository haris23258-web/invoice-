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
"""CREATE TABLE IF NOT EXISTS mobile_tokens(token TEXT PRIMARY KEY,user_id BIGINT,created TEXT)"""
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

@app.route("/mobile")
def mobile():
    return """<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Deewaryn Staff</title><style>
:root{--g:#169b62;--d:#0c251b;--bg:#f3f6f5;--m:#748078;--line:#e1e7e3}
*{box-sizing:border-box}body{margin:0;font-family:Arial;background:var(--bg);color:#17231d}.login{min-height:100vh;background:var(--d);display:grid;place-items:center;padding:20px}
.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:15px;margin-bottom:10px}.box{width:min(440px,100%);background:#fff;border-radius:22px;padding:22px}
h1,h2,h3{margin:0 0 8px}.muted{color:var(--m);font-size:12px}.input{width:100%;padding:12px;border:1px solid var(--line);border-radius:10px;margin-top:10px}
.btn{border:0;border-radius:9px;padding:10px 13px;font-weight:800;text-decoration:none;display:inline-block}.green{background:var(--g);color:#fff}.soft{background:#e8f4ed;color:var(--g)}
.head{background:var(--d);color:#fff;padding:17px 15px}.content{max-width:900px;margin:auto;padding:14px 14px 82px}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.kpi b{display:block;font-size:20px;margin-top:5px}.nav{position:fixed;left:0;right:0;bottom:0;background:#fff;border-top:1px solid var(--line);display:flex;overflow-x:auto}
.nav button{min-width:90px;flex:1;border:0;background:#fff;padding:11px 5px;color:var(--m);font-weight:800}.nav button.on{color:var(--g)}.row{display:flex;gap:8px;align-items:center}.grow{flex:1}
@media(min-width:700px){.grid{grid-template-columns:repeat(4,1fr)}}
</style></head><body><div id="root"></div><script>
const mods=[['home','Home'],['properties','Properties'],['contacts','CRM'],['deals','Deals'],['tasks','Tasks'],['employees','Employees'],['rent','Rent'],['projects','Projects'],['maintenance','Maintenance'],['ledger','Finance']];
let user=null,tab='home';
const esc=x=>String(x??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function api(p,o={}){let t=localStorage.dw_token,h={'Content-Type':'application/json',...(o.headers||{})};if(t)h.Authorization='Bearer '+t;let r=await fetch(p,{...o,headers:h}),d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||('Server '+r.status));return d}
function shell(b){return '<div class="head"><h2>DEEWARYN</h2><div style="opacity:.7">Private Staff Cloud</div></div><div class="content">'+b+'</div><div class="nav">'+mods.map(x=>'<button class="'+(tab==x[0]?'on':'')+'" onclick="go(\''+x[0]+'\')">'+x[1]+'</button>').join('')+'</div>'}
function loginView(){return '<div class="login"><div class="box"><h1>Deewaryn Staff</h1><div class="muted">Cloud login — works even when office laptop is off</div><input id="u" class="input" value="admin" placeholder="Username"><input id="p" class="input" type="password" value="admin123" placeholder="Password"><button class="btn green" style="width:100%;margin-top:12px" onclick="login()">Sign In</button></div></div>'}
async function login(){try{let d=await api('/api/mobile/login',{method:'POST',body:JSON.stringify({username:u.value,password:p.value})});localStorage.dw_token=d.token;localStorage.dw_user=JSON.stringify(d.user);user=d.user;render()}catch(e){alert(e.message)}}
function logout(){localStorage.clear();user=null;render()}function go(x){tab=x;render()}
async function home(){let d=await api('/api/mobile/dashboard');let ks=[['Properties',d.properties],['Active CRM',d.contacts],['Open Deals',d.open_deals],['Commission','PKR '+Number(d.commission||0).toLocaleString()],['Income','PKR '+Number(d.income||0).toLocaleString()],['Expense','PKR '+Number(d.expense||0).toLocaleString()],['Profit','PKR '+Number(d.profit||0).toLocaleString()],['Tasks',d.tasks]];return '<div class="row"><div class="grow"><h2>Command Center</h2><div class="muted">'+esc(user.name)+' • '+esc(user.role)+'</div></div><button class="btn soft" onclick="logout()">Logout</button></div><div class="grid" style="margin-top:12px">'+ks.map(x=>'<div class="card kpi"><span class="muted">'+x[0]+'</span><b>'+x[1]+'</b></div>').join('')+'</div><h3>Follow-ups</h3>'+(d.followups||[]).map(x=>'<div class="card"><b>'+esc(x.name)+'</b><div class="muted">'+esc(x.stage)+' • '+esc(x.followup)+'</div><a class="btn green" href="tel:'+esc(x.phone)+'">Call</a> <a class="btn soft" href="https://wa.me/'+esc(String(x.phone||'').replace(/\D/g,'').replace(/^0/,'92'))+'">WhatsApp</a></div>').join('')}
const prim={properties:'code',contacts:'name',deals:'title',tasks:'title',employees:'name',rent:'tenant',projects:'name',maintenance:'title',ledger:'category'};
async function list(t){let d=await api('/api/mobile/'+t);return '<div class="row"><div class="grow"><h2>'+mods.find(x=>x[0]==t)[1]+'</h2><div class="muted">'+d.length+' records</div></div></div>'+d.map(x=>'<div class="card"><b>'+esc(x[prim[t]])+'</b><div class="muted">'+Object.entries(x).filter(([k,v])=>v&&k!='id'&&k!='created'&&k!=prim[t]).slice(0,5).map(([k,v])=>esc(v)).join(' • ')+'</div>'+(x.phone||x.tenant_phone?'<div style="margin-top:8px"><a class="btn green" href="tel:'+esc(x.phone||x.tenant_phone)+'">Call</a></div>':'')+'</div>').join('')}
async function render(){let r=document.getElementById('root');if(!user){r.innerHTML=loginView();return}r.innerHTML=shell('<div class="card">Loading...</div>');try{r.innerHTML=shell(tab=='home'?await home():await list(tab))}catch(e){r.innerHTML=shell('<div class="card"><b>Error</b><p>'+esc(e.message)+'</p><button class="btn green" onclick="render()">Retry</button></div>')}}
try{user=JSON.parse(localStorage.dw_user||'null')}catch(e){}render();
</script></body></html>"""

try:init_db()
except Exception as e:print("DB init deferred:",e)
