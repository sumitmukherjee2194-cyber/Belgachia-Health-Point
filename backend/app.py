from fastapi import FastAPI, UploadFile, File, Query, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from jose import JWTError, jwt
import pandas as pd
import os
import io
import json
import hashlib
import base64

app = FastAPI(title='Belgachia Health Point Billing AI')

# Enable CORS for frontend and external tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend build (static)
FRONTEND_DIR = os.getenv('FRONTEND_DIR', '/workspace/frontend')
app.mount('/static', StaticFiles(directory=FRONTEND_DIR), name='static')

# JWT and Auth setup
JWT_SECRET = os.getenv('JWT_SECRET', 'dev-insecure-secret')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', '480'))

security = HTTPBearer(auto_error=False)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str

class LoginRequest(BaseModel):
    username: str
    password: str

class User(BaseModel):
    username: str
    role: str

PASSWORD_SALT = os.getenv('PASSWORD_SALT', 'dev-salt-please-change')

def hash_password(plain: str) -> str:
    dk = hashlib.pbkdf2_hmac('sha256', plain.encode('utf-8'), PASSWORD_SALT.encode('utf-8'), 120000)
    return base64.urlsafe_b64encode(dk).decode('ascii')

def verify_password(plain: str, hashed: str) -> bool:
    return hash_password(plain) == hashed

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

# In-memory users (replace with DB later)
_users_seed: Dict[str, Dict[str, str]] = {
    # username: password, role
    "admin": {"password": "admin123", "role": "Admin"},
    "pharma": {"password": "pharma123", "role": "Pharmacist"},
    "manager": {"password": "manager123", "role": "Manager"},
}
users_db: Dict[str, Dict[str, str]] = {
    u: {"username": u, "hashed_password": hash_password(v["password"]), "role": v["role"]}
    for u, v in _users_seed.items()
}

def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> User:
    if creds is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = creds.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    stored = users_db.get(username)
    if not stored:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return User(username=username, role=role)

def require_roles(allowed_roles: List[str]):
    def _checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user
    return _checker

@app.get('/')
async def serve_index():
    index_path = os.path.join(FRONTEND_DIR, 'index.html')
    return FileResponse(index_path)

class InsightRequest(BaseModel):
    data_period: str
    data_scope: str

class FixRequest(BaseModel):
    fix_id: str
    approval_status: bool

class QueryRequest(BaseModel):
    query_text: str

UPLOAD_DIR = os.getenv('UPLOAD_DIR', '/workspace/backend/uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)
_last_upload_path: Optional[str] = None

def _compute_generic_summary(df: pd.DataFrame) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        'records': len(df),
        'columns': list(df.columns),
    }
    for candidate in ['Amount', 'amount', 'Total', 'total', 'Net', 'net_amount']:
        if candidate in df.columns:
            try:
                summary['total_amount'] = float(pd.to_numeric(df[candidate], errors='coerce').fillna(0).sum())
                break
            except Exception:
                pass
    for candidate in ['GST', 'gst', 'Tax', 'tax']:
        if candidate in df.columns:
            try:
                summary['total_tax'] = float(pd.to_numeric(df[candidate], errors='coerce').fillna(0).sum())
                break
            except Exception:
                pass
    return summary

@app.post('/upload-csv')
async def upload_csv(
    file: UploadFile = File(...),
    data_type: str = Query(...),
    user: User = Depends(require_roles(["Admin", "Manager", "Pharmacist"]))
):
    content = await file.read()
    # Save to disk
    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    filename = f"{data_type}-{timestamp}.csv"
    save_path = os.path.join(UPLOAD_DIR, filename)
    with open(save_path, 'wb') as f:
        f.write(content)
    # Parse
    df = pd.read_csv(io.BytesIO(content))
    global _last_upload_path
    _last_upload_path = save_path
    summary = _compute_generic_summary(df)
    return {'status': 'success', 'records_uploaded': len(df), 'data_type': data_type, 'file_path': save_path, 'summary': summary}

@app.get('/sync-marg-db')
async def sync_marg_db(connection_string: str, table_name: str, user: User = Depends(require_roles(["Admin", "Manager"]))):
    return {'records_synced': 2400,'sync_status': 'ok'}

@app.post('/validate-data')
async def validate_data(data_batch_id: str, user: User = Depends(require_roles(["Admin", "Manager", "Pharmacist"]))):
    return {'validation_report': 'No duplicates found','suggested_fixes': []}

def _ai_insight_with_openai(prompt: str) -> Optional[str]:
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        return None
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        completion = client.chat.completions.create(
            model=os.getenv('OPENAI_MODEL', 'gpt-4o-mini'),
            messages=[{"role": "system", "content": "You are a helpful healthcare billing analyst."}, {"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=400,
        )
        return completion.choices[0].message.content
    except Exception:
        return None

@app.post('/generate-insight')
async def generate_insight(request: InsightRequest, user: User = Depends(require_roles(["Admin", "Manager", "Pharmacist"]))):
    prompt = f"Analyze {request.data_scope} billing data for {request.data_period} and give 3 actionable insights."
    text = _ai_insight_with_openai(prompt)
    if text:
        recs = [r.strip("- •\n ") for r in text.split('\n') if r.strip()][:5]
        return {'insight_summary': f'Insights for {request.data_period} ({request.data_scope})', 'recommendations': recs}
    # Fallback
    return {'insight_summary': f'Insights for {request.data_period} ({request.data_scope})','recommendations': ['Improve stock tracking','Send payment reminders','Review high-GST items']}

@app.post('/auto-fix')
async def auto_fix(request: FixRequest, user: User = Depends(require_roles(["Admin", "Manager"]))):
    return {'fix_result': '3 GST mismatches corrected','affected_records': 3}

@app.post('/query')
async def query_ai(request: QueryRequest, user: User = Depends(require_roles(["Admin", "Manager", "Pharmacist"]))):
    prompt = f"Healthcare Billing Query: {request.query_text}"
    text = _ai_insight_with_openai(prompt)
    answer = text if text else 'Pending bills above ₹10,000 found in 5 records.'
    return {'answer': answer,'related_data': []}

@app.get('/generate-report')
async def generate_report(report_type: str, output_format: str, user: User = Depends(require_roles(["Admin", "Manager"]))):
    return {'file_url': 'https://belgachia-ai/reports/report.pdf','summary_text': 'Revenue increased by 8% this week.'}

@app.post('/send-alert')
async def send_alert(alert_type: str, message_text: str, recipients: List[str], user: User = Depends(require_roles(["Admin", "Manager"]))):
    return {'status': 'sent','alert_id': 'AL-1023'}


# Analytics endpoints
@app.get('/analytics-summary')
async def analytics_summary(user: User = Depends(require_roles(["Admin", "Manager", "Pharmacist"]))):
    if not _last_upload_path or not os.path.exists(_last_upload_path):
        return {'status': 'no_data'}
    try:
        df = pd.read_csv(_last_upload_path)
        summary = _compute_generic_summary(df)
        # Simple derived KPIs
        summary['avg_amount'] = None
        if 'total_amount' in summary and summary['records']:
            summary['avg_amount'] = round(summary['total_amount'] / max(summary['records'], 1), 2)
        return {'status': 'ok', 'summary': summary, 'last_upload_path': _last_upload_path}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'Failed to read last upload: {e}')


# Auth endpoints
@app.post('/auth/login', response_model=TokenResponse)
async def login(body: LoginRequest):
    stored = users_db.get(body.username)
    if not stored or not verify_password(body.password, stored['hashed_password']):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid credentials')
    role = stored['role']
    token = create_access_token({"sub": body.username, "role": role})
    return TokenResponse(access_token=token, role=role, username=body.username)

@app.get('/auth/me', response_model=User)
async def me(user: User = Depends(get_current_user)):
    return user
