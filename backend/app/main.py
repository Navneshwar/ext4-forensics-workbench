from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.db.database import init_db
init_db()
app=FastAPI(title="EXT4 Deleted File Recovery Workbench",version="0.4.0")
app.add_middleware(CORSMiddleware,allow_origins=["http://localhost:5173","http://127.0.0.1:5173"],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
app.include_router(router)
@app.get("/")
def root():return {"name":"EXT4 Deleted File Recovery Workbench","version":"0.4.0","docs":"/docs"}
