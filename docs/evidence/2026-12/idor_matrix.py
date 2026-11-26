"""Defensive authorization and IDOR verification matrix for Kura (T6).

Runs authenticated Django test client requests across Student, Teaching Assistant,
Instructor, Registrar, and Admin sessions backed by tracked UserSession rows and
fresh MFA timestamps, verifying both positive authorized controls (200) and
forbidden cross-user / separation-of-duties cells (403).
"""

import csv
import hashlib
import os
import sys
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django  # noqa: E402

django.setup()

from django.utils import timezone  # noqa: E402
from django_otp.plugins.otp_totp.models import TOTPDevice  # noqa: E402
from django_otp.util import random_hex  # noqa: E402

from kura.models import (  # noqa: E402
    Assessment,
    AssessmentAttempt,
    AttemptFile,
    AttemptStatus,
    Course,
    FileContent,
    Grade,
    GradeStatus,
    StoredFile,
    User,
)
from kura.permissions import service_rls_context  # noqa: E402
from kura.tests_security_fixtures import create_authenticated_client  # noqa: E402


def _ensure_onboarded_mfa(user):
    """Ensure a seeded QA user has completed onboarding and TOTP setup."""
    changed = False
    if user.must_change_password:
        user.must_change_password = False
        changed = True
    if not user.mfa_enabled:
        key = random_hex(20)
        user.mfa_enabled = True
        user.mfa_secret = key
        TOTPDevice.objects.get_or_create(user=user, name="default", defaults={"confirmed": True, "key": key})
        changed = True
    if changed:
        user.save(update_fields=["must_change_password", "mfa_enabled", "mfa_secret"])


def main():
    with service_rls_context():
        student_a = User.objects.get(email="student@kura.edu")
        student_b = User.objects.get(email="student2@kura.edu")
        ta = User.objects.get(email="ta@kura.edu")
        instructor = User.objects.get(email="instructor@kura.edu")
        registrar = User.objects.get(email="registrar@kura.edu")
        admin = User.objects.get(email="admin@kura.edu")

        for u in (student_a, student_b, ta, instructor, registrar, admin):
            _ensure_onboarded_mfa(u)

        course = Course.objects.first()
        assessment = Assessment.objects.filter(course=course).first()
        now = timezone.now()

        attempt_a, _ = AssessmentAttempt.objects.get_or_create(
            assessment=assessment,
            student=student_a,
            attempt_no=1,
            defaults={
                "status": AttemptStatus.REQUIRES_MANUAL_GRADING,
                "started_at": now,
                "submitted_at": now,
                "ip_address": "127.0.0.1",
            },
        )

        # Find or create Student B's submitted attempt with a real attached PDF.
        # Migration 0030 locks attempt_files once an attempt leaves IN_PROGRESS, so attach first.
        existing_af = AttemptFile.objects.filter(attempt__assessment=assessment, attempt__student=student_b).first()
        if existing_af is not None:
            attempt_b = existing_af.attempt
            stored_b = existing_af.file
        else:
            last_no = (
                AssessmentAttempt.objects.filter(assessment=assessment, student=student_b)
                .order_by("-attempt_no")
                .values_list("attempt_no", flat=True)
                .first()
                or 0
            )
            attempt_b = AssessmentAttempt.objects.create(
                assessment=assessment,
                student=student_b,
                attempt_no=last_no + 1,
                status=AttemptStatus.IN_PROGRESS,
                started_at=now,
                ip_address="127.0.0.1",
            )
            pdf_bytes = b"%PDF-1.4\n% Student B QA submission\n%%EOF\n"
            stored_b = StoredFile.objects.create(
                uploaded_by=student_b,
                original_filename="student_b_submission.pdf",
                mime_type="application/pdf",
                size_bytes=len(pdf_bytes),
                sha256_hash=hashlib.sha256(pdf_bytes).hexdigest(),
            )
            FileContent.objects.create(file=stored_b, content=pdf_bytes, encryption_version=0)
            AttemptFile.objects.create(attempt=attempt_b, file=stored_b)
            attempt_b.status = AttemptStatus.FULLY_GRADED
            attempt_b.submitted_at = now
            attempt_b.save(update_fields=["status", "submitted_at"])

        # Create a released grade for Student B and a draft grade for Student A.
        grade_b_released, _ = Grade.objects.update_or_create(
            attempt=attempt_b,
            defaults={
                "assessment": assessment,
                "student": student_b,
                "grader": instructor,
                "score": Decimal("88.00"),
                "status": GradeStatus.RELEASED,
                "finalized_at": now,
                "finalized_by": instructor,
                "released_at": now,
                "released_by": instructor,
            },
        )
        grade_a_draft, _ = Grade.objects.update_or_create(
            attempt=attempt_a,
            defaults={
                "assessment": assessment,
                "student": student_a,
                "grader": instructor,
                "score": Decimal("91.00"),
                "status": GradeStatus.DRAFT,
            },
        )

        client_student_a, _ = create_authenticated_client(student_a, fresh_mfa=True)
        client_ta, _ = create_authenticated_client(ta, fresh_mfa=True)
        client_instructor, _ = create_authenticated_client(instructor, fresh_mfa=True)
        client_registrar, _ = create_authenticated_client(registrar, fresh_mfa=True)
        client_admin, _ = create_authenticated_client(admin, fresh_mfa=True)

    cases = [
        # Positive controls confirming authenticated MFA sessions work as intended
        ("Positive control: Student A -> own attempt detail", "GET", client_student_a, f"/attempts/{attempt_a.id}/", (200,)),
        ("Positive control: Instructor -> own course grades", "GET", client_instructor, f"/courses/{course.id}/grades/", (200,)),
        # Required forbidden IDOR / RBAC / separation-of-duties cells
        ("Student A -> Student B attempt detail", "GET", client_student_a, f"/attempts/{attempt_b.id}/", (403, 404)),
        (
            "Student A -> Student B attempt file download",
            "GET",
            client_student_a,
            f"/attempts/{attempt_b.id}/files/{stored_b.id}/download/",
            (403, 404),
        ),
        (
            "Student A -> Student B grade change request",
            "GET",
            client_student_a,
            f"/grades/{grade_b_released.id}/change-request/",
            (403, 404),
        ),
        ("TA -> grade finalize (POST)", "POST", client_ta, f"/grades/{grade_a_draft.id}/finalize/", (403, 404)),
        ("Registrar -> course grades (separation of duties)", "GET", client_registrar, f"/courses/{course.id}/grades/", (403, 404)),
        ("Admin -> course grades (separation of duties)", "GET", client_admin, f"/courses/{course.id}/grades/", (403, 404)),
        ("Student A -> registrar students", "GET", client_student_a, "/registrar/students/", (403, 404)),
        ("TA -> registrar students", "GET", client_ta, "/registrar/students/", (403, 404)),
        ("Instructor -> admin users", "GET", client_instructor, "/admin/users/", (403, 404)),
    ]

    out_dir = Path(__file__).resolve().parent
    csv_path = out_dir / "idor_matrix.csv"
    txt_path = out_dir / "idor_matrix.txt"

    rows = []
    all_passed = True
    lines = ["IDOR / Access Control Matrix Verification Results (T6)", "=" * 60, ""]

    for label, method, client, url, expected in cases:
        resp = client.post(url) if method == "POST" else client.get(url)
        ok = resp.status_code in expected
        if not ok:
            all_passed = False
        result = "PASS" if ok else "FAIL"
        exp_str = "/".join(str(c) for c in expected)
        rows.append([label, method, url, exp_str, resp.status_code, result])
        lines.append(f"{result}: {label}")
        lines.append(f"  {method} {url} -> HTTP {resp.status_code} (expected {exp_str})")
        lines.append("")

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Test", "Method", "URL", "Expected", "Status Code", "Result"])
        writer.writerows(rows)

    lines.append(f"Summary: {sum(1 for r in rows if r[5] == 'PASS')}/{len(rows)} passed")
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
