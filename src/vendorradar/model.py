from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, Date, Boolean
from .db import Base, uid
from datetime import date

class Vendor(Base):
    __tablename__='vendors'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    tenant_id: Mapped[str]=mapped_column(String(100),index=True)
    name: Mapped[str]=mapped_column(String(120))
    service: Mapped[str]=mapped_column(String(160))

class Evidence(Base):
    __tablename__='vendor_evidence'
    id: Mapped[str]=mapped_column(String(36),primary_key=True,default=uid)
    tenant_id: Mapped[str]=mapped_column(String(100),index=True)
    vendor_id: Mapped[str]=mapped_column(String(36),index=True)
    category: Mapped[str]=mapped_column(String(50))
    source_url: Mapped[str]=mapped_column(String(500))
    expires_on: Mapped[date]=mapped_column(Date,nullable=True)
    reviewed: Mapped[bool]=mapped_column(Boolean,default=False)
