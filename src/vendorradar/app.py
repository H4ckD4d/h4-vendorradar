"""Bounded MVP API. Never deploy this demo unchanged with real customer data."""
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta, date
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, Request, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .db import Base, AuditEvent, audit, engine_for_env, uid
from .security import current_actor, require_write
from .model import *

@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = engine_for_env()
    app.state.engine = engine
    if os.getenv('H4_AUTO_CREATE_TABLES') == '1':
        Base.metadata.create_all(engine)
    try:
        yield
    finally:
        engine.dispose()

def session_dep(request: Request):
    with Session(request.app.state.engine) as session:
        yield session

def require_tenant(session: Session, model, entity_id: str, tenant_id: str):
    item = session.scalar(select(model).where(model.id == entity_id, model.tenant_id == tenant_id))
    if item is None:
        raise HTTPException(404, 'Not found')
    return item

app = FastAPI(title='H4 VendorRadar', version='0.1.0', lifespan=lifespan,
              description='Tenant-scoped technical MVP; not production-ready.')

@app.middleware('http')
async def add_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response

@app.get('/healthz', include_in_schema=False)
def healthz():
    return {'ok': True}

@app.get('/v1/audit')
def audit_list(limit:int=Query(default=50,ge=1,le=100),offset:int=Query(default=0,ge=0,le=10000),
               auth=Depends(current_actor),session: Session=Depends(session_dep)):
    rows = session.scalars(select(AuditEvent).where(AuditEvent.tenant_id == auth['tenant_id'])
                           .order_by(AuditEvent.created_at.desc(),AuditEvent.id.desc())
                           .offset(offset).limit(limit)).all()
    return {'events': [{'kind':r.kind,'resource_id':r.resource_id,'actor_id':r.actor_id,
                        'at':r.created_at.isoformat()} for r in rows],
            'limit':limit,'offset':offset}

from urllib.parse import urlparse

class VendorCreate(BaseModel):
    name: str=Field(min_length=2,max_length=120)
    service: str=Field(min_length=2,max_length=160)

class EvidenceCreate(BaseModel):
    category: Literal['security-policy','audit','insurance','contract','other']
    source_url: str=Field(min_length=10,max_length=500)
    expires_on: date|None=None
    reviewed: bool=False

@app.post('/v1/vendors',status_code=201)
def create_vendor(payload: VendorCreate,auth=Depends(require_write),session: Session=Depends(session_dep)):
    vendor=Vendor(tenant_id=auth['tenant_id'],**payload.model_dump())
    session.add(vendor);session.flush();audit(session,auth,'vendor.created',vendor.id);session.commit()
    return {'id':vendor.id,'name':vendor.name}

@app.get('/v1/vendors')
def list_vendors(auth=Depends(current_actor),session: Session=Depends(session_dep)):
    rows=session.scalars(select(Vendor).where(Vendor.tenant_id==auth['tenant_id']).limit(100)).all()
    return [{'id':v.id,'name':v.name,'service':v.service} for v in rows]

@app.post('/v1/vendors/{vendor_id}/evidence',status_code=201)
def add_evidence(vendor_id: str,payload: EvidenceCreate,auth=Depends(require_write),session: Session=Depends(session_dep)):
    require_tenant(session,Vendor,vendor_id,auth['tenant_id'])
    parsed=urlparse(payload.source_url)
    if parsed.scheme!='https' or not parsed.netloc or parsed.username or parsed.password:
        raise HTTPException(422,'Evidence source must be a public HTTPS URL without credentials')
    item=Evidence(tenant_id=auth['tenant_id'],vendor_id=vendor_id,**payload.model_dump())
    session.add(item);session.flush();audit(session,auth,'evidence.registered',item.id);session.commit()
    return {'id':item.id,'vendor_id':vendor_id}

@app.get('/v1/vendors/{vendor_id}/assessment')
def assessment(vendor_id: str,auth=Depends(current_actor),session: Session=Depends(session_dep)):
    vendor=require_tenant(session,Vendor,vendor_id,auth['tenant_id'])
    evidence=session.scalars(select(Evidence).where(Evidence.tenant_id==auth['tenant_id'],Evidence.vendor_id==vendor_id)).all()
    expired=sum(bool(e.expires_on and e.expires_on<date.today()) for e in evidence)
    unreviewed=sum(not e.reviewed for e in evidence)
    score=min(100,max(0,50+(0 if evidence else 35)+expired*20+unreviewed*10-len(evidence)*5))
    return {'vendor_id':vendor.id,'heuristic_risk_score':score,'evidence_count':len(evidence),
        'expired':expired,'unreviewed':unreviewed,'note':'Illustrative prioritization only; not a validated security rating.'}


@app.get('/v1/vendors/expiring')
def expiring_evidence(days: int=Query(default=30,ge=1,le=365),auth=Depends(current_actor),
                      session: Session=Depends(session_dep)):
    from datetime import timedelta
    start=date.today(); end=start+timedelta(days=days)
    evidence=session.scalars(select(Evidence).where(
        Evidence.tenant_id==auth['tenant_id'],Evidence.expires_on >= start,
        Evidence.expires_on <= end).order_by(Evidence.expires_on.asc()).limit(100)).all()
    return {'days':days,'count':len(evidence),'evidence':[{'id':e.id,'vendor_id':e.vendor_id,
            'category':e.category,'expires_on':e.expires_on.isoformat()} for e in evidence]}
