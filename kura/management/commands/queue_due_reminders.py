"""
Queues "due in 24 hours" reminder emails.

Run it every hour (host crontab):
    0 * * * *  cd /path/to/kura && docker compose exec -T web python manage.py queue_due_reminders

It finds every assessment that is already open, visible to students, and due
within the next 24 hours, and queues one reminder for each actively enrolled
student who has not submitted yet. send_queued_emails then sends them.
Each reminder's event_key is "reminder-24h:<assessment>:<student>", so the
database refuses a second copy: running this every hour (or twice by mistake)
never sends a student the same reminder twice.
"""

from django.conf import settings
from django.core.management.base import BaseCommand
from django.urls import reverse
from django.utils import timezone

from kura.models import Assessment, AssessmentAttempt, Enrollment, EnrollmentStatus
from kura.views import queue_email


class Command(BaseCommand):
    help = "Queues reminder emails for assessments due in the next 24 hours."

    def handle(self, *args, **options):
        now = timezone.now()
        queued_count = 0

        # Open, visible assessments that are due within the next 24 hours.
        assessments = Assessment.objects.filter(
            opens_at__lte=now,
            due_date__gt=now,
            due_date__lte=now + timezone.timedelta(hours=24),
            section__is_visible=True,
            section__module__is_visible=True,
        ).select_related("section__module__course")

        for assessment in assessments:
            course = assessment.section.module.course
            link = settings.SITE_URL + reverse("kura:assessment_detail", kwargs={"assessment_id": assessment.id})
            due_text = timezone.localtime(assessment.due_date).strftime("%d %b %Y, %H:%M")

            # Students who already submitted an attempt do not need a reminder.
            submitted_student_ids = set(
                AssessmentAttempt.objects.filter(assessment=assessment, submitted_at__isnull=False).values_list(
                    "student_id", flat=True
                )
            )

            enrollments = Enrollment.objects.filter(
                course=course, status=EnrollmentStatus.ACTIVE, student__is_active=True
            ).select_related("student")
            for enrollment in enrollments:
                if enrollment.student_id in submitted_student_ids:
                    continue
                queue_email(
                    f"reminder-24h:{assessment.id}:{enrollment.student_id}",
                    enrollment.student.email,
                    f"Due soon: {assessment.title}",
                    f"Hello,\n\nThis is a reminder that {assessment.title} ({course.code}) is due on {due_text}, "
                    "and you have not submitted it yet.\n\n"
                    f"Log in to Kura to complete it:\n{link}\n\n"
                    "This is an automatic message from Kura. Please do not reply.",
                )
                queued_count += 1

        # Print only a count, never addresses.
        self.stdout.write(f"Checked {len(assessments)} assessment(s); {queued_count} reminder(s) considered.")
