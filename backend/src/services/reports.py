import time, os, csv, io, hashlib, json
from fastapi import HTTPException
from src.models import Job, Report, Delivery
from src.config.settings import ARTIFACT_DIR
from src.services import archive


def create(db, data):
    j=db.get(Job,data.job_id)
    if not j or j.status!='completed' or not j.approved:
        raise HTTPException(409,'请先选择已完成且获批准的分析结果')
    r=Report(name=data.name, job_id=j.id, destination=data.destination, interval_seconds=data.interval_seconds, next_run=time.time()+data.delay_seconds, enabled=True)
    db.add(r); db.flush()
    return r


def _artifact_path(filename):
    return os.path.join(ARTIFACT_DIR, filename)


def _remove(delivery):
    for name in (delivery.filename, delivery.filename+'.json'):
        try: os.unlink(_artifact_path(name))
        except OSError: pass


def deliver(db, report):
    j=db.get(Job,report.job_id)
    if not j or not j.approved: return
    out=io.StringIO()
    out.write('\ufeff')
    table=j.result.get('table',{})
    cols=table.get('columns',[])
    writer=csv.writer(out)
    def safe(v):
        if isinstance(v,(int,float)) and not isinstance(v,bool): return v
        text=str(v)
        return "'"+text if text.startswith(('=','+','-','@','\t','\r')) else text
    writer.writerow([safe(c['label']) for c in cols])
    for row in table.get('rows',[]): writer.writerow([safe(row.get(c['key'],'')) for c in cols])
    data=out.getvalue().encode('utf-8')
    document={'job':j.name,'params':j.params,'result':j.result,'checksum':hashlib.sha256(data).hexdigest()}
    payload=json.dumps(document,ensure_ascii=False,allow_nan=False).encode('utf-8')
    # 归档立即使用当时生效的密钥落盘；密钥不可用时本轮不投递，下个周期重试。
    version=archive.active_version(db); db.commit()
    with archive.download_lease(db,version,'write'):
        delivery=Delivery(report_id=report.id, created_at=time.time(),
                          checksum=document['checksum'], filename='', destination=report.destination,
                          key_version=version, encryption_state='done', migrated_at=time.time())
        db.add(delivery); db.flush()
        delivery.filename=f'report-{report.id}-delivery-{delivery.id}.csv'
        db.commit()
        try:
            os.makedirs(ARTIFACT_DIR,exist_ok=True)
            archive._atomic_write(_artifact_path(delivery.filename),archive.encrypt_bytes(data,version))
            archive._atomic_write(_artifact_path(delivery.filename+'.json'),archive.encrypt_bytes(payload,version))
        except Exception:
            # 本轮不留下半份归档；计划保持到期状态，下个周期整份重试。
            _remove(delivery)
            db.delete(delivery); db.commit()
            raise
        # 若写入期间已有新密钥生效，本次归档仍需纳入下一轮换密。
        if archive.active_version(db)!=version:
            delivery.encryption_state='pending'; delivery.error=''
            db.commit()
    report.next_run=time.time()+report.interval_seconds
    return delivery


def read_delivery(db, delivery, part='csv'):
    name=delivery.filename+('.json' if part=='json' else '')
    path=_artifact_path(name)
    if not os.path.exists(path): raise HTTPException(404,'归档文件不存在，请重新安排分发')
    try:
        # 先对元数据记录的密钥取租约，再读文件：确保读取期间旧密钥不会被退役。
        with archive.download_lease(db,delivery.key_version):
            with open(path,'rb') as handle: blob=handle.read()
            version=archive.blob_version(blob)
            if version is None: version=delivery.key_version
            if version is not None and version!=delivery.key_version:
                # 并发换密把文件切到了更新的密钥；补一份新密钥租约再解密。
                with archive.download_lease(db,version):
                    data,used=archive.decrypt_bytes(blob)
            else:
                data,used=archive.decrypt_bytes(blob)
    except archive.KeyUnavailable:
        raise HTTPException(409,'该归档的加密密钥已退役或不可用，无法读取') from None
    except ValueError:
        raise HTTPException(500,'归档密文校验失败，请联系业务负责人') from None
    return name, data
