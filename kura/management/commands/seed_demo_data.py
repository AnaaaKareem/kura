from decimal import Decimal
from django.conf import settings
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from django.db import transaction
from django.utils import timezone
from django_otp.plugins.otp_static.models import StaticToken

from kura.models import (
    User,
    Department,
    Role,
    UserRole,
    StaffProfile,
    StudentProfile,
    Course,
    CourseStaff,
    Enrollment,
    Schedule,
    Assessment,
    AcademicLevel,
    GradeComponentType,
    CourseStaffRole,
    EnrollmentStatus,
    SemesterType,
    SessionType,
    DayOfWeek,
)
from kura.permissions import service_rls_context


class Command(BaseCommand):
    help = "Seeds demo accounts and a sample course for testing all six Kura user roles."

    def handle(self, *args, **options):
        """Create or update local demo accounts, roles, and sample course content."""
        # Prevent demo accounts and credentials from being created in production.
        if not settings.DEBUG:
            raise CommandError("This command can only run when DEBUG=True.")

        with service_rls_context():
            with transaction.atomic():
                self._seed()

    def _seed(self):

        password = "KuraPass2026!"

        self.stdout.write("Starting demo data seeding...")

        # 1. Fetch or create all 6 system roles.
        roles = {}
        for role_name in [
            "Admin",
            "Registrar",
            "Department head",
            "Instructor",
            "Teaching assistant",
            "Student",
        ]:
            role, _ = Role.objects.get_or_create(name=role_name)
            roles[role_name] = role

        # Create demo users without changing existing passwords or MFA settings.
        def setup_user(email, first_name, last_name, role_name):
            """Get or create a demo account and assign the requested system role."""
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "first_name": first_name,
                    "last_name": last_name,
                    "is_active": True,
                    "must_change_password": False,
                    "mfa_enabled": False,
                },
            )
            # Only new accounts need the initial demo password (seeded local demo accounts).
            if created:
                user.set_password(password)  # nosemgrep: python.django.security.audit.unvalidated-password.unvalidated-password
                user.save(update_fields=["password"])

            # Assign role.
            UserRole.objects.get_or_create(user=user, role=roles[role_name])

            # Remove the old shared recovery code without deleting the user's other factors.
            StaticToken.objects.filter(device__user=user, token="123456").delete()

            return user

        # 2. Create the demo accounts for all roles.
        admin_user = setup_user("admin@kura.edu", "System", "Admin", "Admin")
        registrar_user = setup_user("registrar@kura.edu", "Rachel", "Registrar", "Registrar")
        head_user = setup_user("depthead@kura.edu", "Alan", "Turing", "Department head")
        instructor_user = setup_user("instructor@kura.edu", "Grace", "Hopper", "Instructor")
        teaching_assistant_user = setup_user("ta@kura.edu", "Alex", "Rivers", "Teaching assistant")
        student_user = setup_user("student@kura.edu", "Alice", "Johnson", "Student")
        student2_user = setup_user("student2@kura.edu", "Bob", "Smith", "Student")

        # 3. Create or update Computer Science Department.
        department, _ = Department.objects.get_or_create(
            code="CS",
            defaults={
                "name": "Department of Computer Science",
                "head_user": head_user,
            },
        )
        if department.head_user != head_user:
            department.head_user = head_user
            department.save()

        # 4. Create Staff and Student Profiles.
        StaffProfile.objects.update_or_create(
            user=admin_user,
            defaults={"department": department, "staff_title": "IT Systems Administrator"},
        )
        StaffProfile.objects.update_or_create(
            user=registrar_user,
            defaults={"department": department, "staff_title": "Registrar Officer"},
        )
        StaffProfile.objects.update_or_create(
            user=head_user,
            defaults={"department": department, "staff_title": "Department Head"},
        )
        StaffProfile.objects.update_or_create(
            user=instructor_user,
            defaults={"department": department, "staff_title": "Lead Instructor"},
        )
        StaffProfile.objects.update_or_create(
            user=teaching_assistant_user,
            defaults={"department": department, "staff_title": "Graduate Teaching Assistant"},
        )

        StudentProfile.objects.update_or_create(
            user=student_user,
            defaults={"department": department, "current_level": AcademicLevel.YEAR_3, "matriculation_year": 2024},
        )
        StudentProfile.objects.update_or_create(
            user=student2_user,
            defaults={"department": department, "current_level": AcademicLevel.YEAR_3, "matriculation_year": 2024},
        )

        # 5. Create demo Course CS301.
        current_time = timezone.now()
        course, _ = Course.objects.update_or_create(
            code="CS301",
            defaults={
                "department": department,
                "title": "Information Security & Applied Cryptography",
                "description": "Core concepts in access control, cryptography, and application security.",
                "semester": SemesterType.SEMESTER_1,
                "academic_year": 2026,
                "is_published": True,
                "published_by": head_user,
                "published_at": current_time,
                "created_by": head_user,
            },
        )

        # 6. Assign Course Staff.
        CourseStaff.objects.update_or_create(
            course=course,
            user=instructor_user,
            defaults={
                "staff_role": CourseStaffRole.LEAD_INSTRUCTOR,
                "can_release_grades": True,
                "assigned_by": head_user,
            },
        )
        CourseStaff.objects.update_or_create(
            course=course,
            user=teaching_assistant_user,
            defaults={
                "staff_role": CourseStaffRole.TEACHING_ASSISTANT,
                "can_release_grades": False,
                "assigned_by": instructor_user,
            },
        )

        # 7. Enroll students.
        Enrollment.objects.update_or_create(
            course=course,
            student=student_user,
            defaults={
                "status": EnrollmentStatus.ACTIVE,
                "enrolled_by": registrar_user,
            },
        )
        Enrollment.objects.update_or_create(
            course=course,
            student=student2_user,
            defaults={
                "status": EnrollmentStatus.ACTIVE,
                "enrolled_by": registrar_user,
            },
        )

        # 8. Create Class Schedule.
        Schedule.objects.update_or_create(
            course=course,
            day=DayOfWeek.MONDAY,
            start_time="10:00:00",
            defaults={
                "instructor": instructor_user,
                "session_type": SessionType.LECTURE,
                "end_time": "12:00:00",
                "location": "Auditorium Hall B",
                "recurrence_start": current_time.date(),
                "recurrence_end": current_time.date() + timezone.timedelta(days=90),
                "created_by": instructor_user,
            },
        )

        # 9. Create a coursework assessment that students answer by uploading a file.
        Assessment.objects.update_or_create(
            course=course,
            title="Coursework 1: Access Control Report",
            defaults={
                "component_type": GradeComponentType.COURSEWORK,
                "description": "Write a short report on least privilege and upload it as a PDF.",
                "max_score": Decimal("20.00"),
                "max_attempts": 2,
                "opens_at": current_time - timezone.timedelta(days=1),
                "due_date": current_time + timezone.timedelta(days=7),
                "created_by": instructor_user,
            },
        )

        self.stdout.write(self.style.SUCCESS("Demo data seeded successfully!"))
