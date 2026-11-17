from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from src.config.database import get_db
from src.models import Report, Delivery, EncryptionKey
from src.schemas.report import ReportInput, KeyAction
from src.middlewares.auth import current_user, admin_only
from src.services import reports, archive
from src.services.audit import record
from src.utils.serialization import report_dict, delivery_dict
router=APIRouter()


def _delivery(db, id):
    d=db.get(Delivery,id)
    if not d: raise HTTPException(404,'归档不存在')
    return d


@router.get('/reports')
def listing(db=Depends(get_db),u=Depends(current_user)):
    return [report_dict(r) for r in db.scalars(select(Report).order_by(Report.id.desc()))]


@router.post('/reports',status_code=201)
def create(data:ReportInput,db=Depends(get_db),u=Depends(admin_only)):
    r=reports.create(db,data); record(db,u.email,'report.schedule',{'id':r.id,'destination':r.destination}); db.commit()
    return report_dict(r)


@router.post('/reports/{id}/toggle')
def toggle(id:int,db=Depends(get_db),u=Depends(admin_only)):
    r=db.get(Report,id)
    if not r:raise HTTPException(404,'分发计划不存在')
    r.enabled=not r.enabled;record(db,u.email,'report.toggle',{'id':id,'enabled':r.enabled});db.commit()
    return report_dict(r)


@router.get('/deliveries')
def deliveries(db=Depends(get_db),u=Depends(current_user)):
    rows=[]
    for d in db.scalars(select(Delivery).order_by(Delivery.id.desc()).limit(100)):
        item=delivery_dict(d)
        key=db.get(EncryptionKey,d.key_version) if d.key_version else None
        item['key_status']=key.status if key else ('retired' if d.key_version else 'plaintext')
        item['key_available']=archive.key_available(d.key_version) if d.key_version else True
        rows.append(item)
    return rows


@router.get('/deliveries/{id}/download')
def download(id:int,format:str='csv',db=Depends(get_db),u=Depends(current_user)):
    if format not in ('csv','json'):raise HTTPException(422,'支持 CSV 或 JSON')
    filename,payload=reports.read_delivery(db,_delivery(db,id),format)
    return Response(payload, media_type='application/json' if format=='json' else 'text/csv; charset=utf-8',
                    headers={'Content-Disposition': f'attachment; filename="{filename}"'})


# ---------------------------------------------------------------- key lifecycle

@router.get('/archive/keys')
def keys(db=Depends(get_db),u=Depends(current_user)):
    return archive.overview(db)


@router.post('/archive/keys/rotate',status_code=201)
def rotate(data:KeyAction|None=None,db=Depends(get_db),u=Depends(admin_only)):
    version=archive.rotate(db,u.email)
    record(db,u.email,'archive.key.rotate',{'version':version});db.commit()
    return {'active_version':version,**archive.overview(db)}


@router.post('/archive/keys/{version}/retire')
def retire(version:int,data:KeyAction|None=None,db=Depends(get_db),u=Depends(admin_only)):
    key=archive.retire(db,version,u.email)
    record(db,u.email,'archive.key.retire',{'version':version});db.commit()
    return {'version':version,'status':key.status}


@router.post('/archive/migrate')
def migrate(data:KeyAction|None=None,db=Depends(get_db),u=Depends(admin_only)):
    retried=archive.retry_failed(db) if (data and data.retry_failed) else 0
    migrated=archive.migrate_pending(db)
    record(db,u.email,'archive.migrate',{'retried':retried,'migrated':migrated});db.commit()
    return {'retried':retried,'migrated':migrated,**archive.overview(db)}
