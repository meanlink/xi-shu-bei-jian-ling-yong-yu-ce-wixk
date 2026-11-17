from sqlalchemy import String, Double, Integer
from sqlalchemy.orm import Mapped, mapped_column
from src.config.database import Base


class EncryptionKey(Base):
    """归档数据密钥的元数据；密钥本体只保存在独立密钥目录。"""
    __tablename__ = 'encryption_keys'
    id: Mapped[int] = mapped_column(primary_key=True)
    version: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), default='active')
    fingerprint: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(150), default='system')
    created_at: Mapped[float] = mapped_column(Double)
    retired_at: Mapped[float | None] = mapped_column(Double, nullable=True)


class ArchiveRotation(Base):
    __tablename__ = 'archive_rotations'
    id: Mapped[int] = mapped_column(primary_key=True)
    target_version: Mapped[int] = mapped_column(Integer, index=True)
    status: Mapped[str] = mapped_column(String(20), default='running')
    created_by: Mapped[str] = mapped_column(String(150))
    created_at: Mapped[float] = mapped_column(Double)
    finished_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    total: Mapped[int] = mapped_column(Integer, default=0)


class KeyLease(Base):
    """跨进程的在途读写租约，退役前必须全部结束。"""
    __tablename__ = 'key_leases'
    id: Mapped[int] = mapped_column(primary_key=True)
    key_version: Mapped[int] = mapped_column(Integer, index=True)
    purpose: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[float] = mapped_column(Double)
    expires_at: Mapped[float] = mapped_column(Double)
