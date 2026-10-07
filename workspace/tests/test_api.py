"""策略 API HTTP 层测试。"""
def _bootstrap(client):
    client.post("/api/cas", json={"ca_id": "corp-root"})
    client.put("/api/domains/corp.example/trust",
               json={"domain": "corp.example", "ca_id": "corp-root"})
    client.post("/api/identities",
                json={"email": "alice@corp.example", "ca_id": "corp-root"})
    client.post("/api/identities",
                json={"email": "bob@corp.example", "ca_id": "corp-root"})


def test_health_and_index(client):
    assert client.get("/api/health").json()["ok"] is True
    r = client.get("/")
    assert r.status_code == 200 and "E2EE" in r.text


def test_api_full_flow_and_manifest(client):
    _bootstrap(client)

    # 预检：bob 可信
    pre = client.post("/api/precheck", json={
        "recipients": [{"email": "bob@corp.example"}]
    }).json()
    assert pre["allowed"] is True

    # 创建 + 冻结 + 发送
    mail = client.post("/api/mails", json={
        "sender": "alice@corp.example", "subject": "s", "body": "hello",
        "idempotency_key": "k1",
    }).json()
    mid = mail["id"]
    # 幂等键
    again = client.post("/api/mails", json={
        "sender": "alice@corp.example", "subject": "s", "body": "hello",
        "idempotency_key": "k1",
    }).json()
    assert again["id"] == mid

    fz = client.post(f"/api/mails/{mid}/freeze", json={
        "recipients": [{"email": "bob@corp.example"}]
    }).json()
    assert fz["status"] == "READY"
    # 重复冻结 → 409
    assert client.post(f"/api/mails/{mid}/freeze", json={
        "recipients": [{"email": "bob@corp.example"}]
    }).status_code == 409

    sent = client.post(f"/api/mails/{mid}/send")
    assert sent.status_code == 200 and sent.json()["status"] == "SENT"
    # 重复发送仍 200，幂等
    assert client.post(f"/api/mails/{mid}/send").json()["status"] == "SENT"

    mf = client.get(f"/api/mails/{mid}/manifest").json()
    assert mf["verification"]["overall_valid"] is True


def test_api_missing_key_returns_423(client):
    _bootstrap(client)
    # 未知收件人（未列入通讯录）
    mail = client.post("/api/mails", json={
        "sender": "alice@corp.example", "subject": "s", "body": "b"
    }).json()
    client.post(f"/api/mails/{mail['id']}/freeze", json={
        "recipients": [{"email": "ghost@corp.example"}]
    })
    r = client.post(f"/api/mails/{mail['id']}/send")
    assert r.status_code == 423
    assert r.json()["status"] == "BLOCKED"


def test_api_external_cert_and_untrusted_ca(client):
    client.post("/api/cas", json={"ca_id": "corp-root"})
    client.post("/api/cas", json={"ca_id": "rogue"})
    client.put("/api/domains/corp.example/trust",
               json={"domain": "corp.example", "ca_id": "corp-root"})
    client.post("/api/identities",
                json={"email": "alice@corp.example", "ca_id": "corp-root"})

    # rogue CA 给 bob 发证书；bob 域只信 corp-root → 证书虽签名有效但锚点不匹配
    cert = client.post("/api/identities", json={
        "email": "bob@corp.example", "ca_id": "rogue"
    }).json()["certificate"]

    mail = client.post("/api/mails", json={
        "sender": "alice@corp.example", "subject": "s", "body": "b"
    }).json()
    fz = client.post(f"/api/mails/{mail['id']}/freeze", json={
        "recipients": [{"email": "bob@corp.example"}]
    }).json()
    assert fz["recipients"][0]["state"] == "UNTRUSTED_CA"

    # 导入被篡改的外部证书 → 400
    bad = dict(cert)
    bad["enc_pub"] = bad["enc_pub"][:-2] + ("AA" if bad["enc_pub"][-2:] != "AA" else "BB")
    r = client.post("/api/certificates", json={"cert": bad})
    assert r.status_code == 400


def test_audit_chain_endpoint(client):
    _bootstrap(client)
    r = client.get("/api/audit/verify").json()
    assert r["ok"] is True and r["entries"] > 0
