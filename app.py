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
    return r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Deewaryn Staff</title>
<style>
:root{--g:#169b62;--d:#0c251b;--bg:#f3f6f5;--m:#748078;--line:#e1e7e3}
*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:var(--bg);color:#17231d}
.login{min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--d);padding:20px}
.box{width:min(430px,100%);background:#fff;border-radius:20px;padding:24px}
h1,h2,h3{margin:0 0 8px}.muted{color:var(--m);font-size:13px}
input{width:100%;padding:13px 14px;margin:8px 0;border:1px solid var(--line);border-radius:10px;font-size:16px}
button,.btn{border:0;border-radius:10px;padding:11px 14px;font-weight:700;cursor:pointer;text-decoration:none;display:inline-block}
.green{background:var(--g);color:white}.soft{background:#e8f4ed;color:var(--g)}
.head{background:var(--d);color:#fff;padding:16px}.content{max-width:1100px;margin:auto;padding:16px 16px 90px}
.row{display:flex;gap:10px;align-items:center}.grow{flex:1}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:14px;margin-bottom:10px}.kpi b{display:block;font-size:22px;margin-top:6px}
.nav{position:fixed;left:0;right:0;bottom:0;background:#fff;border-top:1px solid var(--line);display:flex;overflow-x:auto;z-index:3}
.nav button{min-width:95px;flex:1;background:#fff;color:var(--m);padding:12px 6px;border-radius:0}.nav button.on{color:var(--g);border-top:3px solid var(--g)}
@media(min-width:800px){.grid{grid-template-columns:repeat(4,1fr)}}
</style>
</head>
<body><div id="app"></div>
<script>
const modules=[['home','Home'],['properties','Properties'],['contacts','CRM'],['deals','Deals'],['tasks','Tasks'],['employees','Employees'],['rent','Rent'],['projects','Projects'],['maintenance','Maintenance'],['ledger','Finance']];
let tab='home';
let token=localStorage.getItem('dw_token')||'';
let user=null;
try{user=JSON.parse(localStorage.getItem('dw_user')||'null')}catch(e){user=null}
const esc=v=>String(v??'').replace(/[&<>"]/g,s=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[s]));

async function api(path, opts={}){
  const headers={'Content-Type':'application/json',...(opts.headers||{})};
  if(token) headers.Authorization='Bearer '+token;
  const r=await fetch(path,{...opts,headers});
  const d=await r.json().catch(()=>({}));
  if(r.status===401){logout();throw new Error('Session expired');}
  if(!r.ok) throw new Error(d.error||('Server error '+r.status));
  return d;
}

function loginView(){
  document.getElementById('app').innerHTML=
  '<div class="login"><div class="box"><h1>Deewaryn Staff</h1><div class="muted">Private cloud login — office laptop can stay off.</div>'+
  '<input id="u" value="admin" placeholder="Username"><input id="p" type="password" placeholder="Password">'+
  '<button class="green" style="width:100%;margin-top:10px" onclick="doLogin()">Sign In</button><div id="msg" class="muted" style="margin-top:10px"></div></div></div>';
}

async function doLogin(){
  const msg=document.getElementById('msg'); msg.textContent='Signing in...';
  try{
    const d=await api('/api/mobile/login',{method:'POST',body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})});
    token=d.token; user=d.user;
    localStorage.setItem('dw_token',token); localStorage.setItem('dw_user',JSON.stringify(user));
    tab='home'; render();
  }catch(e){msg.textContent=e.message;}
}
function logout(){localStorage.removeItem('dw_token');localStorage.removeItem('dw_user');token='';user=null;loginView();}
function go(t){tab=t;render();}
function shell(body){
  return '<div class="head"><div class="row"><div class="grow"><h2>DEEWARYN</h2><div style="opacity:.7">Private Staff Cloud</div></div><button class="soft" onclick="logout()">Logout</button></div></div>'+
  '<div class="content">'+body+'</div>'+
  '<div class="nav">'+modules.map(m=>'<button class="'+(tab===m[0]?'on':'')+'" onclick="go(\''+m[0]+'\')">'+m[1]+'</button>').join('')+'</div>';
}
async function home(){
  const d=await api('/api/mobile/dashboard');
  const k=[['Properties',d.properties],['Active CRM',d.contacts],['Open Deals',d.open_deals],['Commission','PKR '+Number(d.commission||0).toLocaleString()],['Income','PKR '+Number(d.income||0).toLocaleString()],['Expense','PKR '+Number(d.expense||0).toLocaleString()],['Profit','PKR '+Number(d.profit||0).toLocaleString()],['Tasks',d.tasks]];
  return '<div class="row"><div class="grow"><h2>Command Center</h2><div class="muted">'+esc(user?.name||'User')+' • '+esc(user?.role||'Staff')+'</div></div></div>'+
  '<div class="grid" style="margin-top:12px">'+k.map(x=>'<div class="card kpi"><span class="muted">'+x[0]+'</span><b>'+x[1]+'</b></div>').join('')+'</div>'+
  '<h3>Follow-ups</h3>'+((d.followups||[]).length?(d.followups||[]).map(x=>'<div class="card"><b>'+esc(x.name)+'</b><div class="muted">'+esc(x.stage)+' • '+esc(x.followup)+'</div>'+(x.phone?'<div style="margin-top:8px"><a class="btn green" href="tel:'+esc(x.phone)+'">Call</a></div>':'')+'</div>').join(''):'<div class="card muted">No follow-ups yet.</div>');
}
const primary={properties:'code',contacts:'name',deals:'title',tasks:'title',employees:'name',rent:'tenant',projects:'name',maintenance:'title',ledger:'category'};
async function listModule(t){
  const d=await api('/api/mobile/'+t);
  const title=modules.find(x=>x[0]===t)?.[1]||t;
  return '<div class="row"><div class="grow"><h2>'+esc(title)+'</h2><div class="muted">'+d.length+' records</div></div></div>'+
  (d.length?d.map(x=>'<div class="card"><b>'+esc(x[primary[t]]||('Record #'+x.id))+'</b><div class="muted">'+Object.entries(x).filter(([k,v])=>v!==null&&v!==''&&k!=='id'&&k!=='created'&&k!==primary[t]).slice(0,6).map(([k,v])=>esc(k)+': '+esc(v)).join(' • ')+'</div></div>').join(''):'<div class="card muted">No records yet.</div>');
}
async function render(){
  if(!token||!user){loginView();return;}
  const a=document.getElementById('app');a.innerHTML=shell('<div class="card">Loading...</div>');
  try{a.innerHTML=shell(tab==='home'?await home():await listModule(tab));}
  catch(e){a.innerHTML=shell('<div class="card"><b>Error</b><p>'+esc(e.message)+'</p><button class="green" onclick="render()">Retry</button></div>');}
}
render();
</script>
</body></html>"""

try:init_db()
except Exception as e:print("DB init deferred:",e)
