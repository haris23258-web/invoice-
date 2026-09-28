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
<title>Deewaryn ERP</title>
<style>
:root{
 --green:#179b62;--green2:#0f7c4d;--gold:#d5a12a;--ink:#10251c;--muted:#718079;
 --bg:#f4f7f5;--card:#ffffff;--line:#e1e8e4;--danger:#b42318;--shadow:0 14px 40px rgba(16,37,28,.08)
}
*{box-sizing:border-box}
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--ink)}
button,input,select,textarea{font:inherit}
.topbar{position:sticky;top:0;z-index:20;background:linear-gradient(135deg,#0b2a1d,#113c2a);color:#fff;padding:16px 22px;box-shadow:0 8px 30px rgba(0,0,0,.12)}
.topin{max-width:1450px;margin:auto;display:flex;align-items:center;gap:18px}
.brand{font-size:26px;font-weight:900;letter-spacing:.5px}.brand span{color:var(--gold)}
.sub{font-size:12px;opacity:.72}.grow{flex:1}.top-actions{display:flex;gap:8px}
.btn{border:0;border-radius:11px;padding:10px 14px;font-weight:800;cursor:pointer;transition:.2s}
.btn:hover{transform:translateY(-1px)}.btn-green{background:var(--green);color:#fff}.btn-soft{background:#edf6f1;color:var(--green2)}.btn-dark{background:#fff;color:#123d2c}.btn-gold{background:var(--gold);color:#1d1d1d}
.layout{max-width:1450px;margin:0 auto;display:grid;grid-template-columns:240px 1fr;min-height:calc(100vh - 76px)}
.sidebar{background:#fff;border-right:1px solid var(--line);padding:18px 12px;position:sticky;top:76px;height:calc(100vh - 76px);overflow:auto}
.navitem{display:flex;align-items:center;gap:10px;width:100%;border:0;background:transparent;padding:12px 14px;border-radius:12px;color:#51645a;font-weight:800;text-align:left;cursor:pointer;margin-bottom:5px}
.navitem.active{background:#eaf6ef;color:var(--green2)}.navitem:hover{background:#f2f7f4}
.content{padding:22px;min-width:0}.pagehead{display:flex;align-items:center;gap:12px;margin-bottom:18px}.pagehead h1{font-size:28px;margin:0}.pagehead .muted{color:var(--muted)}
.grid{display:grid;gap:14px}.kpis{grid-template-columns:repeat(4,minmax(0,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow)}
.kpi{padding:18px;position:relative;overflow:hidden}.kpi:after{content:"";position:absolute;width:80px;height:80px;border-radius:50%;right:-25px;top:-25px;background:rgba(23,155,98,.08)}
.kpi .label{font-size:12px;color:var(--muted);font-weight:800;text-transform:uppercase;letter-spacing:.5px}.kpi .value{font-size:28px;font-weight:900;margin-top:7px}
.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap}.search{flex:1;min-width:220px;background:#fff;border:1px solid var(--line);border-radius:12px;padding:11px 13px}
.tablewrap{overflow:auto}.table{width:100%;border-collapse:collapse;min-width:900px}.table th,.table td{padding:13px 12px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}.table th{background:#f8faf9;color:#64756d;font-size:11px;text-transform:uppercase;letter-spacing:.4px;position:sticky;top:0}
.empty{padding:45px;text-align:center;color:var(--muted)}.chip{display:inline-block;padding:5px 9px;border-radius:999px;background:#eef5f1;color:#456255;font-size:11px;font-weight:800}
.section{padding:18px}.section h3{margin:0 0 12px}.follow{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.follow .item{border:1px solid var(--line);border-radius:14px;padding:13px}
.modal{position:fixed;inset:0;background:rgba(8,24,17,.55);display:none;align-items:center;justify-content:center;z-index:100;padding:18px}.modal.show{display:flex}
.modalbox{background:#fff;border-radius:20px;width:min(760px,100%);max-height:90vh;overflow:auto;box-shadow:0 30px 90px rgba(0,0,0,.25)}
.modalhead{display:flex;align-items:center;padding:18px 20px;border-bottom:1px solid var(--line)}.modalhead h2{margin:0}.modalbody{padding:20px}
.formgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.field label{display:block;font-size:12px;font-weight:800;color:#64756d;margin-bottom:6px}.field input,.field select,.field textarea{width:100%;border:1px solid var(--line);border-radius:10px;padding:11px;background:#fff}.field textarea{min-height:85px;resize:vertical}.full{grid-column:1/-1}
.login{min-height:100vh;background:linear-gradient(135deg,#0b281c,#154833);display:grid;place-items:center;padding:20px}.loginbox{width:min(430px,100%);background:#fff;border-radius:24px;padding:28px;box-shadow:0 30px 100px rgba(0,0,0,.25)}
.loginbox h1{font-size:34px;margin:0}.loginbox h1 span{color:var(--green)}.loginbox p{color:var(--muted)}.loginbox input{width:100%;margin:7px 0;padding:13px;border:1px solid var(--line);border-radius:11px}
.toast{position:fixed;right:20px;bottom:20px;background:#123d2c;color:#fff;padding:13px 16px;border-radius:12px;display:none;z-index:200}
@media(max-width:1000px){.layout{grid-template-columns:1fr}.sidebar{position:fixed;left:0;right:0;bottom:0;top:auto;height:68px;display:flex;z-index:30;overflow-x:auto;padding:7px;border-top:1px solid var(--line);border-right:0}.navitem{min-width:105px;justify-content:center;margin:0}.content{padding-bottom:90px}.kpis{grid-template-columns:repeat(2,1fr)}}
@media(max-width:650px){.content{padding:14px}.kpis{grid-template-columns:1fr 1fr}.follow{grid-template-columns:1fr}.formgrid{grid-template-columns:1fr}.full{grid-column:auto}.brand{font-size:21px}.pagehead h1{font-size:23px}}
</style>
</head>
<body><div id="app"></div><div id="modal" class="modal"></div><div id="toast" class="toast"></div>
<script>
const modules=[
 ['home','Dashboard'],['properties','Properties'],['contacts','CRM Leads'],['deals','Deals'],['tasks','Tasks'],
 ['employees','Employees'],['rent','Rent'],['projects','Projects'],['maintenance','Maintenance'],['ledger','Finance']
];
const forms={
 properties:[['code','Property Code'],['purpose','Purpose','select',['Sale','Rent']],['ptype','Property Type','select',['Full House','Upper Portion','Ground Portion','Lower Portion','Plot','Commercial','Apartment']],['location','Location'],['area','Area / Marla'],['price','Price','number'],['beds','Bedrooms','number'],['baths','Bathrooms','number'],['owner','Owner'],['phone','Phone'],['status','Status','select',['Available','Reserved','Sold','Rented']],['notes','Notes','textarea']],
 contacts:[['name','Client Name'],['phone','Phone'],['email','Email'],['ctype','Type','select',['Buyer','Seller','Tenant','Landlord','Investor']],['budget','Budget','number'],['location','Preferred Location'],['requirement','Requirement','textarea'],['source','Source'],['stage','Stage','select',['New','Follow-up','Visit','Negotiation','Closed','Lost']],['assigned','Assigned To'],['followup','Next Follow-up','date'],['notes','Notes','textarea']],
 deals:[['title','Deal Title'],['client','Client'],['property_code','Property Code'],['stage','Stage','select',['Lead','Visit','Negotiation','Token','Closed Won','Closed Lost']],['deal_value','Deal Value','number'],['commission','Commission','number'],['assigned','Assigned To'],['next_action','Next Action'],['notes','Notes','textarea']],
 tasks:[['title','Task Title'],['related_to','Related To'],['due','Due Date','date'],['priority','Priority','select',['Low','Medium','High','Urgent']],['status','Status','select',['Pending','In Progress','Done']],['assigned','Assigned To'],['notes','Notes','textarea']],
 employees:[['name','Employee Name'],['phone','Phone'],['email','Email'],['role','Role'],['salary','Salary','number'],['visits','Monthly Visits','number'],['calls','Monthly Calls','number'],['properties','Properties Found','number'],['deals','Deals Closed','number'],['expense','Expense','number'],['status','Status','select',['Active','Inactive']],['notes','Notes','textarea']],
 rent:[['property_code','Property Code'],['tenant','Tenant'],['tenant_phone','Tenant Phone'],['owner','Owner'],['monthly_rent','Monthly Rent','number'],['security','Security','number'],['due_day','Due Day','number'],['start_date','Start Date','date'],['agreement_end','Agreement End','date'],['last_paid','Last Paid','date'],['status','Status','select',['Active','Due','Vacated']],['notes','Notes','textarea']],
 projects:[['name','Project Name'],['ptype','Project Type'],['client','Client'],['phone','Phone'],['location','Location'],['contract','Contract Value','number'],['spent','Spent','number'],['progress','Progress %','number'],['status','Status','select',['Planning','Active','On Hold','Completed']],['start_date','Start Date','date'],['end_date','End Date','date'],['notes','Notes','textarea']],
 maintenance:[['title','Job Title'],['client','Client'],['phone','Phone'],['location','Location'],['category','Category'],['priority','Priority','select',['Low','Medium','High','Urgent']],['assigned','Assigned To'],['status','Status','select',['New','In Progress','Waiting','Completed']],['estimate','Estimate','number'],['spent','Spent','number'],['notes','Notes','textarea']],
 ledger:[['dt','Date','date'],['etype','Type','select',['Income','Expense']],['category','Category'],['source','Source'],['amount','Amount','number'],['ref','Reference'],['notes','Notes','textarea']]
};
const titles=Object.fromEntries(modules);
const primary={properties:'code',contacts:'name',deals:'title',tasks:'title',employees:'name',rent:'tenant',projects:'name',maintenance:'title',ledger:'category'};
let tab='home',token=localStorage.getItem('dw_token')||'',user=null;
try{user=JSON.parse(localStorage.getItem('dw_user')||'null')}catch(e){}
const esc=v=>String(v??'').replace(/[&<>"]/g,s=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[s]));
function money(v){return 'PKR '+Number(v||0).toLocaleString()}
function showToast(m){const t=document.getElementById('toast');t.textContent=m;t.style.display='block';setTimeout(()=>t.style.display='none',2200)}
async function api(path,opts={}){
 const h={'Content-Type':'application/json',...(opts.headers||{})}; if(token)h.Authorization='Bearer '+token;
 const r=await fetch(path,{...opts,headers:h}); const d=await r.json().catch(()=>({}));
 if(r.status===401){localStorage.clear();token='';user=null;loginView();throw Error('Session expired')}
 if(!r.ok)throw Error(d.error||('Server '+r.status)); return d;
}
function loginView(){
 document.getElementById('app').innerHTML='<div class="login"><div class="loginbox"><h1>Dee<span>waryn</span></h1><p>Enterprise Staff Management Cloud</p><input id="u" value="admin" placeholder="Username"><input id="p" type="password" placeholder="Password"><button class="btn btn-green" style="width:100%;margin-top:8px" onclick="doLogin()">Secure Sign In</button><div id="msg" style="margin-top:10px;color:var(--danger)"></div></div></div>';
}
async function doLogin(){try{const d=await api('/api/mobile/login',{method:'POST',body:JSON.stringify({username:u.value,password:p.value})});token=d.token;user=d.user;localStorage.setItem('dw_token',token);localStorage.setItem('dw_user',JSON.stringify(user));tab='home';render()}catch(e){msg.textContent=e.message}}
function logout(){localStorage.clear();token='';user=null;loginView()}
function shell(body){
 return '<div class="topbar"><div class="topin"><div><div class="brand">Dee<span>waryn</span></div><div class="sub">Enterprise Command Center</div></div><div class="grow"></div><div class="top-actions"><button class="btn btn-dark" onclick="logout()">Logout</button></div></div></div>'+
 '<div class="layout"><aside class="sidebar">'+modules.map(m=>'<button class="navitem '+(tab===m[0]?'active':'')+'" onclick="go(\''+m[0]+'\')">'+m[1]+'</button>').join('')+'</aside><main class="content">'+body+'</main></div>';
}
function go(t){tab=t;render()}
async function dashboard(){
 const d=await api('/api/mobile/dashboard');
 const ks=[['Properties',d.properties],['Active CRM',d.contacts],['Open Deals',d.open_deals],['Commission',money(d.commission)],['Income',money(d.income)],['Expense',money(d.expense)],['Profit',money(d.profit)],['Tasks',d.tasks]];
 return '<div class="pagehead"><div><h1>Command Center</h1><div class="muted">Welcome '+esc(user?.name||'Admin')+' • '+esc(user?.role||'Administrator')+'</div></div></div>'+
 '<div class="grid kpis">'+ks.map(x=>'<div class="card kpi"><div class="label">'+x[0]+'</div><div class="value">'+x[1]+'</div></div>').join('')+'</div>'+
 '<div class="card section" style="margin-top:16px"><h3>Upcoming Follow-ups</h3><div class="follow">'+((d.followups||[]).length?(d.followups||[]).map(x=>'<div class="item"><b>'+esc(x.name)+'</b><div class="muted">'+esc(x.stage||'')+' • '+esc(x.followup||'')+'</div><div style="margin-top:8px"><a class="btn btn-green" href="tel:'+esc(x.phone||'')+'">Call</a> <a class="btn btn-soft" href="https://wa.me/'+esc(String(x.phone||'').replace(/[^0-9]/g,'').replace(/^0/,'92'))+'">WhatsApp</a></div></div>').join(''):'<div class="empty">No follow-ups yet.</div>')+'</div></div>';
}
async function modulePage(t,q=''){
 const d=await api('/api/mobile/'+t+(q?'?q='+encodeURIComponent(q):''));
 const fields=forms[t]||[];
 const cols=[primary[t],...fields.map(f=>f[0]).filter(x=>x!==primary[t])].slice(0,7);
 return '<div class="pagehead"><div class="grow"><h1>'+esc(titles[t])+'</h1><div class="muted">'+d.length+' records</div></div><button class="btn btn-gold" onclick="openAdd(\''+t+'\')">+ Add New</button></div>'+
 '<div class="toolbar"><input class="search" id="searchBox" placeholder="Search '+esc(titles[t])+'..." value="'+esc(q)+'" onkeydown="if(event.key===\'Enter\')doSearch(\''+t+'\')"><button class="btn btn-soft" onclick="doSearch(\''+t+'\')">Search</button></div>'+
 '<div class="card tablewrap">'+(d.length?'<table class="table"><thead><tr>'+cols.map(c=>'<th>'+esc(labelOf(t,c))+'</th>').join('')+'</tr></thead><tbody>'+d.map(r=>'<tr>'+cols.map(c=>'<td>'+formatCell(c,r[c])+'</td>').join('')+'</tr>').join('')+'</tbody></table>':'<div class="empty">No records yet. Click <b>+ Add New</b> to create the first one.</div>')+'</div>';
}
function labelOf(t,key){const f=(forms[t]||[]).find(x=>x[0]===key);return f?f[1]:key.replace(/_/g,' ')}
function formatCell(k,v){if(v===null||v==='')return '—';if(['price','budget','deal_value','commission','salary','expense','amount','monthly_rent','security','contract','spent','estimate'].includes(k))return money(v);if(['status','stage','priority','purpose','etype'].includes(k))return '<span class="chip">'+esc(v)+'</span>';return esc(v)}
function doSearch(t){modulePage(t,document.getElementById('searchBox').value).then(b=>document.getElementById('app').innerHTML=shell(b))}
function openAdd(t){
 const fs=forms[t]||[];
 const html='<div class="modalbox"><div class="modalhead"><h2>Add '+esc(titles[t])+'</h2><div class="grow"></div><button class="btn btn-soft" onclick="closeModal()">Close</button></div><div class="modalbody"><div class="formgrid">'+fs.map(f=>fieldHtml(f)).join('')+'</div><div style="margin-top:16px;display:flex;justify-content:flex-end;gap:8px"><button class="btn btn-soft" onclick="closeModal()">Cancel</button><button class="btn btn-green" onclick="saveRecord(\''+t+'\')">Save Record</button></div></div></div>';
 const m=document.getElementById('modal');m.innerHTML=html;m.classList.add('show');
}
function fieldHtml(f){
 const [key,label,type='text',opts=[]]=f; const cls=type==='textarea'?'field full':'field';
 if(type==='select')return '<div class="'+cls+'"><label>'+esc(label)+'</label><select id="f_'+key+'"><option value="">Select</option>'+opts.map(o=>'<option>'+esc(o)+'</option>').join('')+'</select></div>';
 if(type==='textarea')return '<div class="'+cls+'"><label>'+esc(label)+'</label><textarea id="f_'+key+'"></textarea></div>';
 return '<div class="'+cls+'"><label>'+esc(label)+'</label><input id="f_'+key+'" type="'+type+'"></div>';
}
function closeModal(){document.getElementById('modal').classList.remove('show')}
async function saveRecord(t){
 const obj={};(forms[t]||[]).forEach(f=>{const el=document.getElementById('f_'+f[0]);if(el&&el.value!=='')obj[f[0]]=el.value});
 try{await api('/api/mobile/'+t,{method:'POST',body:JSON.stringify(obj)});closeModal();showToast('Record saved successfully');render()}catch(e){alert(e.message)}
}
async function render(){
 if(!token||!user){loginView();return}
 const a=document.getElementById('app');a.innerHTML=shell('<div class="card section">Loading...</div>');
 try{a.innerHTML=shell(tab==='home'?await dashboard():await modulePage(tab))}catch(e){a.innerHTML=shell('<div class="card section"><h3>Error</h3><p>'+esc(e.message)+'</p><button class="btn btn-green" onclick="render()">Retry</button></div>')}
}
render();
</script></body></html>"""

try:init_db()
except Exception as e:print("DB init deferred:",e)
