from fastapi import FastAPI, UploadFile, File, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import pandas as pd
import os

app = FastAPI(title='Belgachia Health Point Billing AI')

# Serve frontend build (static)
FRONTEND_DIR = os.getenv('FRONTEND_DIR', '/workspace/frontend')
app.mount('/static', StaticFiles(directory=FRONTEND_DIR), name='static')

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

@app.post('/upload-csv')
async def upload_csv(file: UploadFile = File(...), data_type: str = Query(...)):
    df = pd.read_csv(file.file)
    return {'status': 'success','records_uploaded': len(df),'data_type': data_type}

@app.get('/sync-marg-db')
async def sync_marg_db(connection_string: str, table_name: str):
    return {'records_synced': 2400,'sync_status': 'ok'}

@app.post('/validate-data')
async def validate_data(data_batch_id: str):
    return {'validation_report': 'No duplicates found','suggested_fixes': []}

@app.post('/generate-insight')
async def generate_insight(request: InsightRequest):
    return {'insight_summary': f'Insights for {request.data_period} ({request.data_scope})','recommendations': ['Improve stock tracking','Send payment reminders']}

@app.post('/auto-fix')
async def auto_fix(request: FixRequest):
    return {'fix_result': '3 GST mismatches corrected','affected_records': 3}

@app.post('/query')
async def query_ai(request: QueryRequest):
    return {'answer': 'Pending bills above ₹10,000 found in 5 records.','related_data': []}

@app.get('/generate-report')
async def generate_report(report_type: str, output_format: str):
    return {'file_url': 'https://belgachia-ai/reports/report.pdf','summary_text': 'Revenue increased by 8% this week.'}

@app.post('/send-alert')
async def send_alert(alert_type: str, message_text: str, recipients: list[str]):
    return {'status': 'sent','alert_id': 'AL-1023'}
