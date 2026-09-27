# SPDX-License-Identifier: GPL-3.0-only
#!/usr/bin/env python3
"""googlefind - a small HTTP service for the Google Find Hub trackers of one account.

Built on GoogleFindMyTools (cloned into /gfmt). Asks Google for a tracker's
locations only when a client requests it (POST .../locate); the answer arrives
over an FCM connection kept open for that. In the background it only re-uploads
the precomputed EIDs of custom (µC) trackers daily (Google drops them after
~4 days). Received reports are stored and served over HTTP.

The account login needs a browser, so it is done once with GoogleFindMyTools
on a desktop; its Auth/secrets.json goes to /data/secrets.json.
"""

import hashlib
import logging
import os
import secrets
import sqlite3
import sys
import threading
import time

GFMT = os.environ.get("GFMT_DIR", "/gfmt")
os.chdir(GFMT)
sys.path.insert(0, GFMT)

from fastapi import Depends, FastAPI, Header, HTTPException, Query  # noqa: E402
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer  # noqa: E402

from Auth.fcm_receiver import FcmReceiver  # noqa: E402
from FMDNCrypto.eid_generator import ROTATION_PERIOD, generate_eid  # noqa: E402
from FMDNCrypto.foreign_tracker_cryptor import decrypt  # noqa: E402
from FMDNCrypto.key_derivation import FMDNOwnerOperations  # noqa: E402
from KeyBackup.cloud_key_decryptor import decrypt_aes_gcm  # noqa: E402
from NovaApi.ExecuteAction.LocateTracker.decrypt_locations import is_mcu_tracker, retrieve_identity_key  # noqa: E402
from NovaApi.ExecuteAction.LocateTracker.location_request import create_location_request  # noqa: E402
from NovaApi.ListDevices.nbe_list_devices import request_device_list  # noqa: E402
from NovaApi.nova_request import nova_request  # noqa: E402
from NovaApi.scopes import NOVA_ACTION_API_SCOPE  # noqa: E402
from NovaApi.util import generate_random_uuid  # noqa: E402
from ProtoDecoders import Common_pb2, DeviceUpdate_pb2  # noqa: E402
from ProtoDecoders.decoder import parse_device_list_protobuf, parse_device_update_protobuf  # noqa: E402
from SpotApi.UploadPrecomputedPublicKeyIds.upload_precomputed_public_key_ids import refresh_custom_trackers  # noqa: E402

LOG = logging.getLogger("googlefind")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")

DB_FILE = os.environ.get("DB_FILE", "/data/reports.db")
API_TOKEN = os.environ.get("API_TOKEN", "")
REFRESH_INTERVAL_S = int(os.environ.get("REFRESH_INTERVAL_H", "24")) * 3600
DEVICES_INTERVAL_S = 3600
# EIDs handed out for ringing cover this much clock skew either side of now
RING_EID_WINDOW_S = 6 * 3600

app = FastAPI(title="googlefind")
_bearer = HTTPBearer(auto_error=False)
_db_lock = threading.Lock()
_db = sqlite3.connect(DB_FILE, check_same_thread=False)
_db.execute("""CREATE TABLE IF NOT EXISTS reports (
    device_id TEXT, time INTEGER, latitude REAL, longitude REAL, altitude INTEGER,
    accuracy REAL, status INTEGER, own INTEGER, semantic TEXT, received INTEGER,
    UNIQUE(device_id, time, latitude, longitude))""")
_db.commit()

_devices = {}           # canonic id -> {"id", "name", "custom"}
_devices_at = 0
_pending = {}           # request uuid -> (device id, threading.Event)
_state = {"started": int(time.time()), "fcm": False, "last_refresh": None, "last_locate": None,
          "last_report": None, "last_error": None}


def error(msg):
    LOG.error(msg)
    _state["last_error"] = {"time": int(time.time()), "message": msg}


def check_token(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
                x_api_token: str | None = Header(None)):
    """Bearer token, or X-Api-Token when a reverse proxy uses Authorization for Basic Auth."""
    if not API_TOKEN:
        return
    token = x_api_token or (credentials.credentials if credentials else "")
    if not secrets.compare_digest(token, API_TOKEN):
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})


def load_devices(force=False):
    global _devices, _devices_at
    if not force and _devices and time.time() - _devices_at < DEVICES_INTERVAL_S:
        return _devices
    device_list = parse_device_list_protobuf(request_device_list())
    devices = {}
    for device in device_list.deviceMetadata:
        if device.identifierInformation.type == DeviceUpdate_pb2.IDENTIFIER_ANDROID:
            ids = device.identifierInformation.phoneInformation.canonicIds.canonicId
        else:
            ids = device.identifierInformation.canonicIds.canonicId
        for cid in ids:
            devices[cid.id] = {"id": cid.id, "name": device.userDefinedDeviceName,
                               "custom": is_mcu_tracker(device.information.deviceRegistration)}
    _devices, _devices_at = devices, time.time()
    return device_list


def decrypt_update(device_update):
    """Decrypted reports of a location response (same logic as GoogleFindMyTools)."""
    registration = device_update.deviceMetadata.information.deviceRegistration
    identity_key = retrieve_identity_key(registration)
    is_mcu = is_mcu_tracker(registration)
    locations = device_update.deviceMetadata.information.locationInformation.reports.recentLocationAndNetworkLocations

    pairs = list(zip(locations.networkLocations, locations.networkLocationTimestamps))
    if locations.HasField("recentLocation"):
        pairs.append((locations.recentLocation, locations.recentLocationTimestamp))

    out = []
    for loc, ts in pairs:
        report = {"time": int(ts.seconds), "latitude": None, "longitude": None, "altitude": None,
                  "accuracy": 0, "status": int(loc.status), "own": True, "semantic": None}
        if loc.status == Common_pb2.Status.SEMANTIC:
            report["semantic"] = loc.semanticLocation.locationName
        else:
            enc = loc.geoLocation.encryptedReport
            if enc.publicKeyRandom == b"":
                plain = decrypt_aes_gcm(hashlib.sha256(identity_key).digest(), enc.encryptedLocation)
            else:
                offset = 0 if is_mcu else loc.geoLocation.deviceTimeOffset
                plain = decrypt(identity_key, enc.encryptedLocation, enc.publicKeyRandom, offset)
            proto = DeviceUpdate_pb2.Location()
            proto.ParseFromString(plain)
            report.update(latitude=proto.latitude / 1e7, longitude=proto.longitude / 1e7,
                          altitude=proto.altitude, accuracy=loc.geoLocation.accuracy,
                          own=bool(enc.isOwnReport))
        out.append(report)
    return out


def on_fcm(hex_payload):
    try:
        update = parse_device_update_protobuf(hex_payload)
        request_uuid = update.fcmMetadata.requestUuid
        pending = _pending.pop(request_uuid, None)
        if pending:
            device_id = pending[0]
        else:
            ids = update.deviceMetadata.identifierInformation.canonicIds.canonicId
            device_id = ids[0].id if ids else None
        if not device_id:
            LOG.info("FCM message without a known device, ignored")
            return
        reports = decrypt_update(update)
        now = int(time.time())
        with _db_lock:
            _db.executemany(
                "INSERT OR IGNORE INTO reports VALUES (?,?,?,?,?,?,?,?,?,?)",
                [(device_id, r["time"], r["latitude"], r["longitude"], r["altitude"], r["accuracy"],
                  r["status"], int(r["own"]), r["semantic"], now) for r in reports])
            _db.commit()
        _state["last_report"] = now
        LOG.info("%s: %d report(s) received", device_id, len(reports))
        if pending:
            pending[1].set()
    except BaseException as e:  # GoogleFindMyTools calls exit() on key errors
        error(f"decoding FCM message failed: {e!r}")


def fcm_token():
    token = FcmReceiver().register_for_location_updates(on_fcm)
    _state["fcm"] = True
    return token


def locate(device_id):
    request_uuid = generate_random_uuid()
    event = threading.Event()
    _pending[request_uuid] = (device_id, event)
    payload = create_location_request(device_id, fcm_token(), request_uuid)
    if nova_request(NOVA_ACTION_API_SCOPE, payload) is None:
        _pending.pop(request_uuid, None)
        raise RuntimeError("Google rejected the location request (see log)")
    _state["last_locate"] = int(time.time())
    return event


def refresh():
    refresh_custom_trackers(load_devices(force=True))
    _state["last_refresh"] = int(time.time())
    LOG.info("custom tracker EIDs refreshed")


def refresh_worker():
    while True:
        try:
            refresh()
            delay = REFRESH_INTERVAL_S
        except BaseException as e:
            error(f"refresh failed: {e!r}")
            delay = 3600
        time.sleep(delay)


def fcm_worker():
    # Connect early so the first locate request does not wait for the FCM login
    try:
        fcm_token()
    except BaseException as e:
        error(f"FCM start failed: {e!r}")


@app.on_event("startup")
def start():
    threading.Thread(target=refresh_worker, daemon=True, name="refresh").start()
    threading.Thread(target=fcm_worker, daemon=True, name="fcm").start()


@app.get("/health")
def health():
    return _state


@app.get("/api/devices", dependencies=[Depends(check_token)])
def devices():
    try:
        load_devices()
    except BaseException as e:
        raise HTTPException(502, f"device list failed: {e!r}")
    with _db_lock:
        last = dict(_db.execute("SELECT device_id, MAX(time) FROM reports GROUP BY device_id").fetchall())
    return [dict(d, last_report=last.get(d["id"])) for d in _devices.values()]


@app.get("/api/devices/{device_id}/reports", dependencies=[Depends(check_token)])
def reports(device_id: str, since: int = 0, limit: int = Query(500, le=5000)):
    with _db_lock:
        rows = _db.execute(
            "SELECT time, latitude, longitude, altitude, accuracy, status, own, semantic, received "
            "FROM reports WHERE device_id = ? AND time >= ? ORDER BY time DESC LIMIT ?",
            (device_id, since, limit)).fetchall()
    keys = ("time", "latitude", "longitude", "altitude", "accuracy", "status", "own", "semantic", "received")
    return [dict(zip(keys, row), own=bool(row[6])) for row in rows]


@app.post("/api/devices/{device_id}/locate", dependencies=[Depends(check_token)])
def locate_now(device_id: str, wait: int = Query(0, ge=0, le=60)):
    """Ask Google for the current locations; with wait=N block up to N s for the
    answer, which is then available from .../reports."""
    try:
        event = locate(device_id)
    except BaseException as e:
        raise HTTPException(502, f"{e!r}")
    answered = event.wait(wait) if wait else False
    return {"requested": True, "answered": answered}


def find_device(device_id):
    """The device list entry of a canonic id, or None."""
    device_list = load_devices(force=True)
    for device in device_list.deviceMetadata:
        if device.identifierInformation.type == DeviceUpdate_pb2.IDENTIFIER_ANDROID:
            ids = device.identifierInformation.phoneInformation.canonicIds.canonicId
        else:
            ids = device.identifierInformation.canonicIds.canonicId
        if any(cid.id == device_id for cid in ids):
            return device
    return None


@app.get("/api/devices/{device_id}/ring", dependencies=[Depends(check_token)])
def ring_material(device_id: str):
    """What a phone needs to ring the tracker itself over Bluetooth (FMDN Beacon Actions):
    the ringing key, which authorises ringing only (it cannot decrypt locations), and the
    EIDs the tracker may be advertising now, to recognise it among nearby trackers."""
    try:
        device = find_device(device_id)
    except BaseException as e:
        raise HTTPException(502, f"device list failed: {e!r}")
    if device is None:
        raise HTTPException(404, "Unknown device")
    registration = device.information.deviceRegistration
    try:
        identity_key = retrieve_identity_key(registration)
    except BaseException as e:  # GoogleFindMyTools calls exit() on key errors
        raise HTTPException(502, f"identity key unavailable: {e!r}")

    keys = FMDNOwnerOperations()
    keys.generate_keys(identity_key)
    if keys.ringing_key is None:
        raise HTTPException(502, "ringing key derivation failed")

    if is_mcu_tracker(registration):
        # Custom (µC) trackers broadcast one static EID, see get_next_eids
        eids = [generate_eid(identity_key, 0)]
    else:
        # The tracker's counter runs from its pairing date, rotating every ROTATION_PERIOD
        pair_date = registration.pairDate
        start = int(time.time()) - RING_EID_WINDOW_S - pair_date
        offset = max(0, start - (start % ROTATION_PERIOD))
        end = int(time.time()) + RING_EID_WINDOW_S - pair_date
        eids = []
        while offset <= end:
            eid = generate_eid(identity_key, offset)
            if eid not in eids:
                eids.append(eid)
            offset += ROTATION_PERIOD
    return {"ring_key": keys.ringing_key.hex(), "eids": [e.hex() for e in eids]}


@app.post("/api/refresh", dependencies=[Depends(check_token)])
def refresh_now():
    try:
        refresh()
    except BaseException as e:
        raise HTTPException(502, f"{e!r}")
    return {"refreshed": _state["last_refresh"]}
