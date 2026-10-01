# ---------- lambda_function.py : CampusCare backend (S3 + SNS only) ----------
import json, os, re, time, base64, hashlib, hmac, secrets
from datetime import datetime, timezone, timedelta
import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
sns = boto3.client("sns")

# ---------- config (Lambda environment variables) ----------
BUCKET = os.environ["BUCKET"]
TOPIC_ARN = os.environ["TOPIC_ARN"]
TOKEN_SECRET = os.environ["TOKEN_SECRET"].encode()   # long random string
ADMIN_USER = os.environ["ADMIN_USER"]
ADMIN_PASS = os.environ["ADMIN_PASS"]

IST = timezone(timedelta(hours=5, minutes=30))
EXT = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp"}
TYPES = ["Maintenance", "Cleanliness", "Complaint", "Suggestion", "Lost & Found", "Other"]
STATUSES = ["Open", "In Progress", "Resolved"]
ID_RE = re.compile(r"^[A-Za-z0-9_-]{3,30}$")
MAX_IMAGE_BYTES = 3 * 1024 * 1024
TOKEN_HOURS = 8


# ---------- small helpers ----------
# CORS is handled here in the code. Keep the Function URL's own CORS setting OFF (blank),
# otherwise the browser receives the headers twice and blocks the request.
CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "content-type,authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Max-Age": "86400",
}


def resp(code, body):
    return {"statusCode": code, "headers": {"Content-Type": "application/json", **CORS},
            "body": json.dumps(body)}


def now_str():
    return datetime.now(IST).strftime("%Y-%m-%dT%H:%M:%S")


def b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def same(a, b):
    return hmac.compare_digest(str(a).encode(), str(b).encode())


# ---------- tokens (signed with HMAC, no extra libraries needed) ----------
def make_token(user):
    payload = dict(user, exp=int(time.time()) + TOKEN_HOURS * 3600)
    p = b64e(json.dumps(payload).encode())
    sig = b64e(hmac.new(TOKEN_SECRET, p.encode(), hashlib.sha256).digest())
    return f"{p}.{sig}"


def read_token(event):
    auth = (event.get("headers") or {}).get("authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        p, sig = auth[7:].split(".")
        good = b64e(hmac.new(TOKEN_SECRET, p.encode(), hashlib.sha256).digest())
        if not same(sig, good):
            return None
        payload = json.loads(b64d(p))
        return payload if payload["exp"] > time.time() else None
    except Exception:
        return None


# ---------- passwords (PBKDF2, never stored in plain text) ----------
def hash_pw(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


def user_key(uid):
    return f"users/{uid.lower()}.json"


def register(d):
    uid, name, email, pw = (str(d.get(k, "")).strip() for k in ("id", "name", "email", "password"))
    if not ID_RE.match(uid):
        return resp(400, {"error": "Enrollment number: 3-30 letters, digits, - or _ only."})
    if not name or "@" not in email or len(email) > 100:
        return resp(400, {"error": "Enter your name and a valid email."})
    if not 8 <= len(pw) <= 72:
        return resp(400, {"error": "Password must be 8-72 characters."})
    salt = secrets.token_bytes(16)
    record = {"id": uid, "name": name[:60], "email": email, "salt": salt.hex(),
              "hash": hash_pw(pw, salt), "created": now_str()}
    try:
        # IfNoneMatch="*" means: only create if this account does not exist yet
        s3.put_object(Bucket=BUCKET, Key=user_key(uid), Body=json.dumps(record),
                      ContentType="application/json", IfNoneMatch="*")
    except ClientError as e:
        if e.response["Error"]["Code"] in ("PreconditionFailed", "ConditionalRequestConflict"):
            return resp(409, {"error": "An account with this enrollment number already exists."})
        raise
    return resp(200, {"ok": True})


def login(d):
    role, uid, pw = d.get("role"), str(d.get("id", "")).strip(), str(d.get("password", ""))
    user = None
    if role == "admin":
        if same(uid, ADMIN_USER) and same(pw, ADMIN_PASS):
            user = {"sub": ADMIN_USER, "role": "admin", "name": "Admin", "email": ""}
    elif role == "student" and ID_RE.match(uid):
        try:
            rec = json.loads(s3.get_object(Bucket=BUCKET, Key=user_key(uid))["Body"].read())
            if same(hash_pw(pw, bytes.fromhex(rec["salt"])), rec["hash"]):
                user = {"sub": rec["id"], "role": "student", "name": rec["name"], "email": rec["email"]}
        except ClientError:
            pass
    if not user:
        return resp(401, {"error": "Wrong ID or password."})
    return resp(200, {"token": make_token(user), "role": user["role"], "name": user["name"],
                      "email": user["email"], "id": user["sub"]})


# ---------- reports ----------
def json_keys():
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix="reports/"):
        keys += [o["Key"] for o in page.get("Contents", []) if o["Key"].endswith(".json")]
    return keys


def integrity_hash(r):
    core = {k: r.get(k, "") for k in ("reportId", "type", "title", "location", "description",
                                       "reporterId", "reporterName", "reporterEmail", "timestamp")}
    return hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()


def submit(user, d):
    if user["role"] != "student":
        return resp(403, {"error": "Only students can submit reports."})
    if d.get("type") not in TYPES:
        return resp(400, {"error": "Choose a valid report type."})
    if any(not str(d.get(k, "")).strip() for k in ("title", "location", "description")):
        return resp(400, {"error": "Title, location and description are required."})

    raw, ctype = None, None
    img = d.get("image")
    if img and img.get("data"):
        ctype = img.get("contentType")
        if ctype not in EXT:
            return resp(400, {"error": "Only JPG, PNG or WEBP images are allowed."})
        raw = base64.b64decode(img["data"])
        if len(raw) > MAX_IMAGE_BYTES:
            return resp(400, {"error": "Image is too large."})

    nums = [int(m.group(1)) for k in json_keys() if (m := re.fullmatch(r"reports/CC-(\d+)\.json", k))]
    n = max(nums, default=0) + 1
    for _ in range(8):
        rid = f"CC-{n:03d}"
        report = {
            "reportId": rid, "type": d["type"], "title": d["title"].strip()[:100],
            "location": d["location"].strip()[:100], "description": d["description"].strip()[:1000],
            "reporterId": user["sub"], "reporterName": user["name"], "reporterEmail": user["email"],
            "image": f"{rid}.{EXT[ctype]}" if raw else "",
            "timestamp": now_str(), "status": "Open",
        }
        report["hash"] = integrity_hash(report)
        report["audit"] = [{"at": report["timestamp"], "action": "Created", "by": user["name"]}]
        try:
            # Create-only write: if two people pick the same number, the loser retries with the next one
            s3.put_object(Bucket=BUCKET, Key=f"reports/{rid}.json", Body=json.dumps(report, indent=2),
                          ContentType="application/json", IfNoneMatch="*")
            break
        except ClientError as e:
            if e.response["Error"]["Code"] in ("PreconditionFailed", "ConditionalRequestConflict"):
                n += 1
                continue
            raise
    else:
        return resp(503, {"error": "The server is busy. Please try again."})

    if raw:
        try:
            s3.put_object(Bucket=BUCKET, Key=f"reports/{report['image']}", Body=raw, ContentType=ctype)
        except ClientError:
            s3.delete_object(Bucket=BUCKET, Key=f"reports/{rid}.json")   # do not keep a half-saved report
            raise

    notified = True
    try:
        sns.publish(TopicArn=TOPIC_ARN, Subject="New CampusCare Report", Message=(
            "A new campus report has been submitted.\n\n"
            f"Report ID: {rid}\nType: {report['type']}\nTitle: {report['title']}\n"
            f"Location: {report['location']}\nReported By: {report['reporterName']}\n"))
    except ClientError as e:
        print("SNS publish failed:", e)
        notified = False
    return resp(200, {"reportId": rid, "notified": notified})


def list_reports(user):
    out = []
    for key in json_keys():
        r = json.loads(s3.get_object(Bucket=BUCKET, Key=key)["Body"].read())
        if user["role"] != "admin" and r.get("reporterId") != user["sub"]:
            continue                                    # students only see their own reports
        if r.get("image"):
            r["imageUrl"] = s3.generate_presigned_url(
                "get_object", Params={"Bucket": BUCKET, "Key": f"reports/{r['image']}"}, ExpiresIn=3600)
        if user["role"] == "admin":
            r["integrityOk"] = (r.get("hash") == integrity_hash(r))
        r.pop("hash", None)
        out.append(r)
    out.sort(key=lambda x: x["reportId"], reverse=True)
    return resp(200, out)


def update_status(user, d):
    if user["role"] != "admin":
        return resp(403, {"error": "Only admins can change status."})
    rid, status = str(d.get("reportId", "")), d.get("status")
    if not re.fullmatch(r"CC-\d+", rid) or status not in STATUSES:
        return resp(400, {"error": "Invalid report or status."})
    key = f"reports/{rid}.json"
    try:
        r = json.loads(s3.get_object(Bucket=BUCKET, Key=key)["Body"].read())
    except ClientError:
        return resp(404, {"error": "Report not found."})
    r["status"] = status
    r["audit"].append({"at": now_str(), "action": f"Status changed to {status}", "by": user["name"]})
    s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(r, indent=2), ContentType="application/json")
    return resp(200, {"ok": True})


# ---------- router ----------
def lambda_handler(event, context):
    http = event["requestContext"]["http"]
    method, path = http["method"], re.sub(r"/+", "/", http["path"]).rstrip("/") or "/"
    if method == "OPTIONS":                       # the browser's "am I allowed?" check before a real request
        return {"statusCode": 204, "headers": CORS, "body": ""}
    try:
        raw = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            raw = base64.b64decode(raw).decode()
        body = json.loads(raw)
    except ValueError:
        return resp(400, {"error": "Invalid JSON"})

    if method == "POST" and path == "/login":
        return login(body)
    if method == "POST" and path == "/register":
        return register(body)

    user = read_token(event)
    if not user:
        return resp(401, {"error": "Please log in."})
    if method == "GET" and path == "/reports":
        return list_reports(user)
    if method == "POST" and path == "/reports":
        return submit(user, body)
    if method == "POST" and path == "/status":
        return update_status(user, body)
    return resp(404, {"error": "Not found"})
