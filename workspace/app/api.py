"""策略 API（FastAPI）。"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .crypto import InvalidCertificate
from .gateway import Gateway, SpoolTransport, TransportError
from .storage import NotFound, StorageError, Store
from . import policy


class CAIn(BaseModel):
    ca_id: str = Field(min_length=1)


class TrustIn(BaseModel):
    domain: str
    ca_id: str


class PolicyIn(BaseModel):
    domain: str
    mode: str  # ENFORCE / OPPORTUNISTIC


class IdentityIn(BaseModel):
    email: str
    ca_id: str
    ttl_seconds: float = 90 * 86400


class ExternalCertIn(BaseModel):
    cert: dict


class RevokeIn(BaseModel):
    serial: str


class DirectoryIn(BaseModel):
    remove: list[str] = []


class RecipientIn(BaseModel):
    email: str
    mode: Optional[str] = None
    cleartext_ack: bool = False


class MailIn(BaseModel):
    sender: str
    subject: str = ""
    body: str = ""
    cleartext_ack: list[str] = []
    idempotency_key: Optional[str] = None


class FreezeIn(BaseModel):
    recipients: list[RecipientIn]


class PrecheckIn(BaseModel):
    recipients: list[RecipientIn]
    at: Optional[float] = None


def create_app(
    db_path: str = "./data/gateway.db",
    spool_dir: str = "./data/spool",
    *,
    fail_closed_on_revoked: bool = True,
    store: Optional[Store] = None,
    gateway: Optional[Gateway] = None,
) -> FastAPI:
    app = FastAPI(
        title="企业邮件端到端加密策略网关",
        version="1.0",
        description="密钥快照冻结 / 强制加密 fail-closed / 可验证投递清单",
    )

    if gateway is not None:
        app.state.store = gateway.store
        app.state.gw = gateway
    else:
        app.state.store = store or Store(db_path)
        transport = SpoolTransport(spool_dir, clock=app.state.store.now)
        app.state.gw = Gateway(
            app.state.store, transport,
            fail_closed_on_revoked=fail_closed_on_revoked,
        )

    gw: Gateway = app.state.gw

    def error(code: int, msg: str, detail=None):
        return JSONResponse(status_code=code,
                            content={"error": msg, "detail": detail})

    # ------------------------------------------------ 管理面

    @app.post("/api/cas", status_code=201, tags=["管理面"])
    def create_ca(body: CAIn):
        try:
            return gw.create_ca(body.ca_id)
        except StorageError as exc:
            raise HTTPException(409, str(exc))

    @app.get("/api/cas", tags=["管理面"])
    def list_cas():
        return {"cas": gw.store.list_cas()}

    @app.put("/api/domains/{domain}/trust", tags=["管理面"])
    def set_trust(domain: str, body: TrustIn):
        body.domain = domain
        try:
            return gw.set_domain_trust(domain, body.ca_id)
        except NotFound as exc:
            raise HTTPException(404, str(exc))

    @app.put("/api/domains/{domain}/policy", tags=["管理面"])
    def set_policy(domain: str, body: PolicyIn):
        body.domain = domain
        try:
            return gw.set_domain_policy(domain, body.mode)
        except StorageError as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/identities", status_code=201, tags=["管理面"])
    def issue_identity(body: IdentityIn):
        try:
            cert = gw.issue_identity(body.email, body.ca_id,
                                     ttl_seconds=body.ttl_seconds)
            return {"certificate": cert,
                    "private_keys": gw.store.get_private_keys(body.email)}
        except StorageError as exc:
            raise HTTPException(400, str(exc))
        except NotFound as exc:
            raise HTTPException(404, str(exc))

    @app.post("/api/identities/rotate", status_code=201, tags=["管理面"])
    def rotate(body: IdentityIn):
        try:
            cert = gw.rotate_identity(body.email, body.ca_id,
                                      ttl_seconds=body.ttl_seconds)
            return {"certificate": cert}
        except StorageError as exc:
            raise HTTPException(400, str(exc))
        except NotFound as exc:
            raise HTTPException(404, str(exc))

    @app.post("/api/certificates", status_code=201, tags=["管理面"])
    def provision_cert(body: ExternalCertIn):
        try:
            return {"certificate": gw.provision_external_cert(body.cert)}
        except NotFound as exc:
            raise HTTPException(404, str(exc))
        except InvalidCertificate as exc:
            raise HTTPException(400, f"外部证书校验失败: {exc}")

    @app.post("/api/certificates/revoke", tags=["管理面"])
    def revoke(body: RevokeIn):
        try:
            return gw.revoke_certificate(body.serial)
        except NotFound as exc:
            raise HTTPException(404, str(exc))

    @app.post("/api/directory/update", tags=["管理面"])
    def directory_update(body: DirectoryIn):
        return gw.update_directory(remove=body.remove)

    @app.get("/api/certificates", tags=["管理面"])
    def list_certificates(email: Optional[str] = None):
        return {"certificates": gw.store.list_certificates(email)}

    # ------------------------------------------------ 预检 / 邮件

    @app.post("/api/precheck", tags=["发送面"])
    def precheck(body: PrecheckIn):
        recipients = [r.model_dump() for r in body.recipients]
        return gw.precheck(recipients, at=body.at)

    @app.post("/api/mails", status_code=201, tags=["发送面"])
    def create_mail(body: MailIn):
        try:
            return gw.create_mail(
                sender=body.sender, subject=body.subject, body=body.body,
                cleartext_ack=body.cleartext_ack,
                idempotency_key=body.idempotency_key,
            )
        except StorageError as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/mails", tags=["发送面"])
    def list_mails():
        return {"mails": gw.store.list_mails()}

    @app.get("/api/mails/{mail_id}", tags=["发送面"])
    def get_mail(mail_id: str):
        try:
            return gw.store.get_mail(mail_id)
        except NotFound as exc:
            raise HTTPException(404, str(exc))

    @app.post("/api/mails/{mail_id}/freeze", tags=["发送面"])
    def freeze(mail_id: str, body: FreezeIn):
        try:
            return gw.freeze(mail_id, [r.model_dump() for r in body.recipients])
        except NotFound as exc:
            raise HTTPException(404, str(exc))
        except StorageError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/mails/{mail_id}/send", tags=["发送面"])
    def send_mail(mail_id: str):
        try:
            result = gw.send(mail_id)
            if result["status"] == "BLOCKED":
                return JSONResponse(status_code=423, content=result)
            if result["status"] == "SEND_FAILED":
                return JSONResponse(status_code=503, content=result)
            return result
        except NotFound as exc:
            raise HTTPException(404, str(exc))
        except StorageError as exc:
            raise HTTPException(409, str(exc))
        except TransportError as exc:
            raise HTTPException(503, str(exc))

    @app.post("/api/mails/{mail_id}/resubmit", status_code=201, tags=["发送面"])
    def resubmit(mail_id: str):
        try:
            return gw.resubmit(mail_id)
        except NotFound as exc:
            raise HTTPException(404, str(exc))

    @app.get("/api/mails/{mail_id}/manifest", tags=["清单"])
    def manifest(mail_id: str, verify: bool = True):
        try:
            return gw.build_manifest(mail_id, verify=verify)
        except NotFound as exc:
            raise HTTPException(404, str(exc))

    @app.get("/api/audit/verify", tags=["清单"])
    def audit_verify():
        return gw.store.verify_audit_chain()

    @app.get("/api/audit", tags=["清单"])
    def audit_list(limit: int = 100):
        return {"entries": gw.store.list_audit(limit)}

    @app.get("/api/health", tags=["系统"])
    def health():
        return {
            "ok": True,
            "catalog_version": gw.store.catalog_version(),
            "fail_closed_on_revoked": gw.fail_closed_on_revoked,
            "default_mode": policy.DEFAULT_MODE,
        }

    # ------------------------------------------------ 静态预检页面

    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(os.path.join(static_dir, "index.html"))

    return app


app = create_app()
