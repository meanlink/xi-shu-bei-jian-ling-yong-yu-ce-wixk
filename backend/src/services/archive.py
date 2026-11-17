"""归档静态加密、密钥轮换与存量迁移。

密钥本体写在 ARCHIVE_KEY_DIR（与 ARTIFACT_DIR 分离），数据库中只保存版本、
状态和指纹。归档文件使用 AES-256-GCM 封装，AAD 绑定密钥版本。
"""
import base64
import hashlib
import os
import struct
import time
import uuid
from contextlib import contextmanager

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError

from src.config.database import Session
from src.config.settings import ARCHIVE_KEY_DIR, ARTIFACT_DIR
from src.models import ArchiveRotation, Delivery, EncryptionKey, KeyLease

MAGIC = b'SPARARC1'
AAD_PREFIX = b'spare-croston-archive:'
LEASE_SECONDS = 60


class KeyUnavailable(Exception):
    pass


# ---------------------------------------------------------------- key storage

def ensure_dirs():
    artifact = os.path.realpath(ARTIFACT_DIR)
    keys = os.path.realpath(ARCHIVE_KEY_DIR)
    if artifact == keys or artifact.startswith(keys + os.sep) or keys.startswith(artifact + os.sep):
        raise RuntimeError('归档密钥目录必须与归档文件目录分开保存，不能互相包含')
    os.makedirs(artifact, exist_ok=True)
    os.makedirs(keys, mode=0o700, exist_ok=True)


def key_path(version):
    return os.path.join(ARCHIVE_KEY_DIR, f'archive-v{int(version):04d}.key')


def _disk_versions():
    try:
        names = os.listdir(ARCHIVE_KEY_DIR)
    except FileNotFoundError:
        return []
    return [int(n[len('archive-v'):-len('.key')]) for n in names
            if n.startswith('archive-v') and n.endswith('.key') and n[9:-4].isdigit()]


def _write_key_material(version, raw):
    ensure_dirs()
    path = key_path(version)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(base64.b64encode(raw))
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


def _read_key_material(version):
    try:
        with open(key_path(version), 'rb') as handle:
            return base64.b64decode(handle.read())
    except (FileNotFoundError, ValueError):
        raise KeyUnavailable(f'归档密钥 v{version} 不可用') from None


def _fingerprint(raw):
    return hashlib.sha256(raw).hexdigest()


def _generate(version):
    raw = AESGCM.generate_key(bit_length=256)
    _write_key_material(version, raw)
    return raw


def _next_version(rows):
    return max([r.version for r in rows] + _disk_versions() + [0]) + 1


# ------------------------------------------------------------------ encryption

def encrypt_bytes(plaintext, version):
    key = _read_key_material(version)
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, plaintext, AAD_PREFIX + str(int(version)).encode())
    return MAGIC + struct.pack('>I', int(version)) + nonce + sealed


def is_encrypted(blob):
    return blob.startswith(MAGIC)


def blob_version(blob):
    if not is_encrypted(blob):
        return None
    return struct.unpack('>I', blob[len(MAGIC):len(MAGIC) + 4])[0]


def decrypt_bytes(blob):
    version = blob_version(blob)
    if version is None:
        return blob, None
    nonce = blob[len(MAGIC) + 4:len(MAGIC) + 16]
    sealed = blob[len(MAGIC) + 16:]
    try:
        return AESGCM(_read_key_material(version)).decrypt(nonce, sealed, AAD_PREFIX + str(version).encode()), version
    except InvalidTag:
        raise ValueError('归档密文校验失败') from None


def key_available(version):
    if version is None:
        return True
    return os.path.exists(key_path(version))


def _atomic_write(path, data):
    ensure_dirs()
    tmp = f'{path}.tmp-{uuid.uuid4().hex}'
    try:
        with open(tmp, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# ---------------------------------------------------------------- key lifecycle

def active_key(db, lock=False):
    query = select(EncryptionKey).where(EncryptionKey.status == 'active').order_by(EncryptionKey.version.desc())
    if lock:
        query = query.with_for_update()
    key = db.scalar(query)
    if key:
        return key
    if lock:
        # 并发首次使用时，另一进程可能已建好密钥；加锁后重查。
        key = db.scalar(query)
        if key:
            return key
    return _bootstrap(db, lock)


def active_version(db):
    key = active_key(db)
    db.commit()
    return key.version


def ensure_active():
    """启动时保证存在生效密钥，供首次分发与页面展示。"""
    ensure_dirs()
    with Session() as db:
        active_key(db, lock=True)
        db.commit()


def _bootstrap(db, lock=False):
    rows = list(db.scalars(select(EncryptionKey).with_for_update() if lock else select(EncryptionKey)))
    existing = next((r for r in rows if r.status == 'active'), None)
    if existing:
        return existing
    version = _next_version(rows)
    try:
        raw = _generate(version)
    except FileExistsError:
        # 另一进程生成同版本密钥但尚未提交；交给下一次调用重新判定。
        db.rollback()
        raise KeyUnavailable('归档密钥正在初始化，请稍后重试') from None
    key = EncryptionKey(version=version, status='active', fingerprint=_fingerprint(raw),
                        created_by='system', created_at=time.time())
    db.add(key)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        try:
            os.unlink(key_path(version))
        except FileNotFoundError:
            pass
        existing = db.scalar(select(EncryptionKey).where(EncryptionKey.version == version))
        if existing:
            return existing
        raise
    return key


def rotate(db, actor):
    """新建生效密钥，并把存量归档标记为待迁移。可安全重复调用。"""
    rows = list(db.scalars(select(EncryptionKey).with_for_update()))
    current = next((r for r in rows if r.status == 'active'), None)
    if current is None:
        current = _bootstrap(db, lock=True)
    version = _next_version(rows + [current])
    raw = _generate(version)
    db.add(EncryptionKey(version=version, status='active', fingerprint=_fingerprint(raw),
                         created_by=actor, created_at=time.time()))
    db.execute(update(EncryptionKey).where(EncryptionKey.id == current.id).values(status='rotating'))
    db.execute(update(ArchiveRotation).where(ArchiveRotation.status == 'running')
               .values(status='superseded', finished_at=time.time()))
    total = db.scalar(select(func.count()).select_from(Delivery)
                      .where(or_(Delivery.key_version.is_(None), Delivery.key_version != version)))
    db.add(ArchiveRotation(target_version=version, status='running', created_by=actor,
                           created_at=time.time(), total=int(total or 0)))
    # 正在迁移的文件保持 migrating，由当前迁移流程收尾后自行重新排队。
    db.execute(update(Delivery)
               .where(or_(Delivery.key_version.is_(None), Delivery.key_version != version),
                      Delivery.encryption_state.in_(('pending', 'done', 'failed')))
               .values(encryption_state='pending', error=''))
    db.commit()
    return version


def retire(db, version, actor):
    key = db.scalar(select(EncryptionKey).where(EncryptionKey.version == version).with_for_update())
    if not key:
        raise HTTPException(404, '归档密钥不存在')
    if key.status == 'retired':
        return key
    if key.status == 'active':
        raise HTTPException(409, '当前生效密钥不能退役，请先轮换到新密钥')
    remaining = db.scalar(select(func.count()).select_from(Delivery)
                          .where(Delivery.key_version == version))
    if remaining:
        raise HTTPException(409, f'仍有 {int(remaining)} 份归档使用 v{version}，全部换密后才能退役')
    plaintext = db.scalar(select(func.count()).select_from(Delivery)
                          .where(Delivery.key_version.is_(None)))
    if plaintext:
        raise HTTPException(409, f'仍有 {int(plaintext)} 份明文归档未完成迁移，不能退役旧密钥')
    db.execute(delete(KeyLease).where(KeyLease.expires_at <= time.time()))
    leases = db.scalar(select(func.count()).select_from(KeyLease)
                       .where(KeyLease.key_version == version, KeyLease.expires_at > time.time()))
    if leases:
        raise HTTPException(409, '仍有在途下载正在使用该密钥，请稍后重试')
    try:
        os.unlink(key_path(version))
    except FileNotFoundError:
        pass
    key.status = 'retired'
    key.retired_at = time.time()
    db.commit()
    return key


# ------------------------------------------------------------------- migration

def recover(db):
    """中断恢复：把遗留的 migrating 文件重新排队。"""
    db.execute(update(Delivery).where(Delivery.encryption_state == 'migrating')
               .values(encryption_state='pending'))
    db.commit()


def retry_failed(db):
    result = db.execute(update(Delivery).where(Delivery.encryption_state == 'failed')
                        .values(encryption_state='pending', error=''))
    db.commit()
    return result.rowcount or 0


def migrate_pending(db, limit=10):
    # 兜底对账：任何已完成归档只要不是当前生效密钥，就重新排队，
    # 防止轮换与并发写入交错时漏掉某份归档。
    version = active_version(db)
    db.execute(update(Delivery)
               .where(Delivery.encryption_state == 'done',
                      or_(Delivery.key_version.is_(None), Delivery.key_version != version))
               .values(encryption_state='pending', error=''))
    db.commit()
    ids = list(db.scalars(select(Delivery.id).where(Delivery.encryption_state == 'pending')
                          .order_by(Delivery.id).limit(limit)))
    migrated = 0
    for delivery_id in ids:
        if migrate_one(db, delivery_id):
            migrated += 1
    return migrated


def migrate_one(db, delivery_id):
    claimed = db.execute(update(Delivery)
                         .where(Delivery.id == delivery_id, Delivery.encryption_state == 'pending')
                         .values(encryption_state='migrating', error='')).rowcount
    db.commit()
    if not claimed:
        return False
    try:
        delivery = db.get(Delivery, delivery_id)
        if delivery is None:
            return False
        version = active_version(db)
        db.commit()
        names = [delivery.filename, delivery.filename + '.json']
        present = [name for name in names if os.path.exists(os.path.join(ARTIFACT_DIR, name))]
        if not present:
            raise FileNotFoundError('归档文件不存在')
        # 先在内存中完成全部解密与重加密；任一份失败都不改动磁盘原文件。
        prepared = []
        already_current = True
        for name in present:
            source = os.path.join(ARTIFACT_DIR, name)
            with open(source, 'rb') as handle:
                plaintext, used = decrypt_bytes(handle.read())
            if used != version:
                already_current = False
                prepared.append((source, encrypt_bytes(plaintext, version)))
        if already_current:
            _finalize(db, delivery_id, version)
            return True
        # 逐文件原子替换：每个归档文件只会在旧密文与完整新密文之间切换，
        # 不会出现半份文件。若中途失败/中断，未替换的文件仍是原可读版本，
        # 下一轮迁移会只处理仍非当前密钥的文件。
        for source, blob in prepared:
            _atomic_write(source, blob)
        _finalize(db, delivery_id, version)
        return True
    except Exception as error:  # 单份失败保留原可读版本（写入前均为临时文件）
        db.rollback()
        db.execute(update(Delivery)
                   .where(Delivery.id == delivery_id, Delivery.encryption_state == 'migrating')
                   .values(encryption_state='failed', error=str(error)[:900]))
        db.commit()
        return False


def _finalize(db, delivery_id, used_version):
    current = active_version(db)
    state = 'done' if used_version == current else 'pending'
    db.execute(update(Delivery)
               .where(Delivery.id == delivery_id, Delivery.encryption_state == 'migrating')
               .values(key_version=used_version, encryption_state=state, error='',
                       migrated_at=time.time()))
    db.commit()


# ---------------------------------------------------------------------- leases

@contextmanager
def download_lease(db, version, purpose='download'):
    # 明文存量尚未分配密钥，无需租约；迁移会先分配密钥再换密。
    if version is None:
        yield
        return
    # 与退役共用密钥行的行锁：租约与退役互斥，退役请求不会在检查后
    # 与一次新的在途读取擦肩而过。
    key = db.scalar(select(EncryptionKey).where(EncryptionKey.version == int(version))
                    .with_for_update())
    if key is None or key.status == 'retired' or not os.path.exists(key_path(version)):
        db.rollback()
        raise KeyUnavailable(f'归档密钥 v{version} 已退役或不可用')
    lease = KeyLease(key_version=version, purpose=purpose, created_at=time.time(),
                     expires_at=time.time() + LEASE_SECONDS)
    db.add(lease)
    db.commit()
    try:
        yield
    finally:
        try:
            db.execute(delete(KeyLease).where(KeyLease.id == lease.id))
            db.commit()
        except Exception:
            db.rollback()


# -------------------------------------------------------------------- overview

STATE_LABELS = {'pending': '待迁移', 'migrating': '迁移中', 'failed': '失败', 'done': '完成'}


def overview(db):
    keys = list(db.scalars(select(EncryptionKey).order_by(EncryptionKey.version.desc())))
    active = next((k.version for k in keys if k.status == 'active'), None)
    usage = dict(db.execute(select(Delivery.key_version, func.count()).group_by(Delivery.key_version)).all())
    states = dict(db.execute(select(Delivery.encryption_state, func.count())
                             .group_by(Delivery.encryption_state)).all())
    leases = dict(db.execute(select(KeyLease.key_version, func.count())
                             .where(KeyLease.expires_at > time.time())
                             .group_by(KeyLease.key_version)).all())
    key_rows = []
    for key in keys:
        files = int(usage.get(key.version, 0))
        can_retire = (key.status == 'rotating' and files == 0
                      and not leases.get(key.version))
        key_rows.append({'version': key.version, 'status': key.status,
                         'fingerprint': key.fingerprint, 'created_by': key.created_by,
                         'created_at': key.created_at, 'retired_at': key.retired_at,
                         'files': files, 'in_use_leases': int(leases.get(key.version, 0)),
                         'can_retire': can_retire})
    rotations = []
    for rotation in db.scalars(select(ArchiveRotation).order_by(ArchiveRotation.id.desc()).limit(10)):
        done = int(usage.get(rotation.target_version, 0))
        failed = int(states.get('failed', 0))
        pending = int(states.get('pending', 0)) + int(states.get('migrating', 0))
        if rotation.status == 'superseded':
            status = 'superseded'
        elif pending == 0 and failed == 0:
            status = 'completed'
        elif failed:
            status = 'attention'
        else:
            status = 'running'
        rotations.append({'id': rotation.id, 'target_version': rotation.target_version,
                          'status': status, 'created_by': rotation.created_by,
                          'created_at': rotation.created_at, 'finished_at': rotation.finished_at,
                          'total': rotation.total, 'done': done, 'pending': pending, 'failed': failed})
    return {'active_version': active,
            'keys': key_rows,
            'rotations': rotations,
            'states': {name: {'label': label, 'count': int(states.get(name, 0))}
                       for name, label in STATE_LABELS.items()},
            'legacy_plaintext': int(usage.get(None, 0))}
