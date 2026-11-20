"""
sign_freshness.py — חותם "תעודת טריות" לרשימת המחשבים המורשים.

הקובץ הזה מועתק לריפו הרישיונות (tools/sign_freshness.py) ורץ שם ב-GitHub Actions
(ראו freshness.yml). הוא עומד בפני עצמו: ספריית התקן, ו-cryptography רק לחתימה.

שני שלבים, בשתי משימות (jobs) נפרדות של ה-workflow:

  sign      (יש לו את מפתח הטריות, אין לו הרשאת כתיבה לריפו)
            קורא את allowed.json, בודק שהוא חתום במפתח הראשי (אחרת נכשל, והבעלים מקבל
            מייל), וחותם תעודה: {"kind", "schema", "issued_at", "list_sha256"}.

  assemble  (יש לו הרשאת כתיבה, אין לו את המפתח, ואין לו שום ספרייה חיצונית)
            מצרף את התעודה ל-allowed.json של אותו commit ובודק שה-SHA256 שבתעודה הוא
            של אותה רשימה. כותב קובץ אחד: {"freshness": התעודה, "list": הרשימה}.

מה מפתח הטריות יכול ומה לא:
  - הוא מעיד רק "הרשימה הזו (לפי ה-SHA256 שלה) בתוקף נכון ל-issued_at".
  - הוא לא יכול להוסיף מחשב ולא לכבות או להדליק את האכיפה: התוכנה בודקת את חתימת
    המפתח הראשי על הרשימה עצמה, והתעודה מתקבלת רק אם ה-SHA256 שבה הוא של אותה רשימה.

מפתח הטריות מגיע ממשתנה הסביבה LAWMIND_FRESHNESS_KEY (Secret ב-GitHub): 32 בתים
של Ed25519, ב-base64. הוא לא נכתב לשום קובץ.

שימוש:
    python sign_freshness.py sign     --list allowed.json --cert-out certificate.json
    python sign_freshness.py assemble --list allowed.json --cert certificate.json --out freshness.json
    python sign_freshness.py --list allowed.json --out freshness.json        (שני השלבים יחד)
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path

# cryptography מיובא רק בתוך הפונקציות שחותמות / מאמתות חתימה: שלב ה-assemble רץ בלי
# שום ספרייה חיצונית (במשימה שיש לה הרשאת כתיבה לריפו לא מתקינים כלום).

# המפתח הציבורי הראשי (זה שחותם על allowed.json). ציבורי, זהה ל-_LICENSE_PUBKEY_B64
# שב-license_service.py. אם המפתח הראשי מוחלף (keygen.py) — לעדכן גם כאן.
LIST_PUBKEY_B64 = "2ADOAIpZVE3N2PFzM33QrwCaGJlQ50jxQH6R/TYEec0="

FRESHNESS_KIND = "lawmind-license-freshness"
FRESHNESS_SCHEMA = 1
BUNDLE_KIND = "lawmind-license-freshness-bundle"
KEY_ENV = "LAWMIND_FRESHNESS_KEY"


def canonical_payload(obj: dict) -> bytes:
    """הבתים שנחתמים: כל השדות פרט ל-sig, בצורה קנונית. זהה ל-license_service."""
    payload = {k: v for k, v in obj.items() if k != "sig"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def list_digest(list_obj: dict) -> str:
    return hashlib.sha256(canonical_payload(list_obj)).hexdigest()


def verify_list(list_obj: dict, pubkey_b64: str = "") -> bool:
    """האם הרשימה חתומה במפתח הראשי."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64 or LIST_PUBKEY_B64))
        pub.verify(base64.b64decode(list_obj.get("sig") or ""), canonical_payload(list_obj))
        return True
    except Exception:
        return False


def certificate_matches(cert, list_obj: dict) -> bool:
    """התעודה מהסוג הנכון, עם תאריך תקין, וה-SHA256 שבה הוא של הרשימה הזו. בלי בדיקת חתימה."""
    if not isinstance(cert, dict) or cert.get("kind") != FRESHNESS_KIND:
        return False
    if cert.get("schema") != FRESHNESS_SCHEMA or cert.get("list_sha256") != list_digest(list_obj):
        return False
    try:
        issued = datetime.datetime.fromisoformat(str(cert.get("issued_at")).replace("Z", "+00:00"))
    except Exception:
        return False
    return issued.tzinfo is not None and bool(cert.get("sig"))


def verify_certificate(cert, list_obj: dict, pubkeys_b64) -> bool:
    """האם התעודה תקפה לרשימה הזו וחתומה באחד מהמפתחות (לבדיקה אחרי פרסום)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not certificate_matches(cert, list_obj):
        return False
    try:
        sig = base64.b64decode(cert.get("sig") or "")
    except Exception:
        return False
    for pubkey_b64 in pubkeys_b64:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64)).verify(
                sig, canonical_payload(cert))
            return True
        except Exception:
            continue
    return False


def load_key_from_env():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    raw_b64 = (os.environ.get(KEY_ENV) or "").strip()
    if not raw_b64:
        raise SystemExit(f"[!] חסר Secret בשם {KEY_ENV} (מפתח הטריות).")
    try:
        raw = base64.b64decode(raw_b64, validate=True)
    except Exception:
        raise SystemExit(f"[!] {KEY_ENV} אינו base64 תקין.") from None
    if len(raw) != 32:
        raise SystemExit(f"[!] {KEY_ENV} צריך להיות 32 בתים ב-base64 (התקבלו {len(raw)}).")
    return Ed25519PrivateKey.from_private_bytes(raw)


def make_certificate(list_obj: dict, key, now=None) -> dict:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cert = {
        "kind": FRESHNESS_KIND,
        "schema": FRESHNESS_SCHEMA,
        "issued_at": now.astimezone(datetime.timezone.utc).isoformat(timespec="seconds"),
        "list_sha256": list_digest(list_obj),
    }
    cert["sig"] = base64.b64encode(key.sign(canonical_payload(cert))).decode()
    return cert


def make_bundle(list_obj: dict, key, now=None) -> dict:
    return {"kind": BUNDLE_KIND, "schema": 1,
            "freshness": make_certificate(list_obj, key, now), "list": list_obj}


def read_list(list_path: Path) -> dict:
    try:
        list_obj = json.loads(list_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise SystemExit(f"[!] לא ניתן לקרוא את {list_path}: {e}") from None
    if not isinstance(list_obj, dict) or not isinstance(list_obj.get("machines"), dict):
        raise SystemExit(f"[!] {list_path} אינו רשימת מחשבים תקינה.")
    return list_obj


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sign(list_path: Path, cert_path: Path, key, pubkey_b64: str = "") -> dict:
    """שלב החתימה: בודק את החתימה הראשית על הרשימה, חותם תעודה וכותב אותה לבדה."""
    list_obj = read_list(list_path)
    if not verify_list(list_obj, pubkey_b64):
        raise SystemExit(f"[!] {list_path} אינו חתום במפתח הראשי — לא חותמים עליו תעודת טריות.")
    cert = make_certificate(list_obj, key)
    _write_json(cert_path, cert)
    return cert


def assemble(list_path: Path, cert_path: Path, out_path: Path) -> dict:
    """שלב הפרסום: מצרף תעודה חתומה לרשימה שהיא מאשרת. בלי מפתח ובלי ספריות חיצוניות."""
    list_obj = read_list(list_path)
    try:
        cert = json.loads(cert_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise SystemExit(f"[!] לא ניתן לקרוא את התעודה {cert_path}: {e}") from None
    if not certificate_matches(cert, list_obj):
        raise SystemExit("[!] התעודה אינה מתאימה ל-allowed.json הזה (הרשימה השתנתה בין החתימה "
                         "לפרסום, או שהתעודה פגומה). לא מפרסמים.")
    bundle = {"kind": BUNDLE_KIND, "schema": 1, "freshness": cert, "list": list_obj}
    _write_json(out_path, bundle)
    return bundle


def build(list_path: Path, out_path: Path, key, pubkey_b64: str = "") -> dict:
    """שני השלבים יחד (הרצה מקומית ובדיקות)."""
    list_obj = read_list(list_path)
    if not verify_list(list_obj, pubkey_b64):
        raise SystemExit(f"[!] {list_path} אינו חתום במפתח הראשי — לא חותמים עליו תעודת טריות.")
    bundle = make_bundle(list_obj, key)
    _write_json(out_path, bundle)
    return bundle


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="חתימת תעודת טריות לרשימת המחשבים")
    parser.add_argument("step", nargs="?", choices=("sign", "assemble"),
                        help="sign = חתימה בלבד; assemble = צירוף לרשימה; בלי = שניהם")
    parser.add_argument("--list", default="allowed.json", help="רשימת המחשבים החתומה")
    parser.add_argument("--cert-out", help="sign: קובץ התעודה שייכתב")
    parser.add_argument("--cert", help="assemble: קובץ התעודה החתומה")
    parser.add_argument("--out", default="freshness.json", help="קובץ הפלט (תעודה + רשימה)")
    args = parser.parse_args(argv)

    if args.step == "sign":
        if not args.cert_out:
            parser.error("sign דורש --cert-out")
        cert = sign(Path(args.list), Path(args.cert_out), load_key_from_env())
        print(f"[OK] signed: issued_at={cert['issued_at']} list_sha256={cert['list_sha256'][:16]}... "
              f"-> {args.cert_out}")
        return 0
    if args.step == "assemble":
        if not args.cert:
            parser.error("assemble דורש --cert")
        bundle = assemble(Path(args.list), Path(args.cert), Path(args.out))
    else:
        bundle = build(Path(args.list), Path(args.out), load_key_from_env())
    cert = bundle["freshness"]
    print(f"[OK] freshness: issued_at={cert['issued_at']} list_sha256={cert['list_sha256'][:16]}... "
          f"machines={len(bundle['list']['machines'])} -> {args.out}")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sys.exit(main())
