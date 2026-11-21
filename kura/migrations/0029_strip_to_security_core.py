"""
Strip Kura down to its security core.

Removes the module/section/item tree, online exams (answer keys, questions, timers), grade appeals and grade weighting.
Assessments and attendance sessions now belong to a course directly, and course materials are a flat list (CourseFile).

The row-level security policies on grades, grade_history and assessment_attempts joined through modules and sections.
They are dropped first and recreated here, joining assessments.course_id instead, with the same rules as migration 0026.
"""

import django.db.models.deletion
import uuid
from django.db import migrations, models

NOT_ADMIN_OR_REGISTRAR = """
    NOT EXISTS (
        SELECT 1 FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id::text = current_setting('kura.current_user_id', true)
        AND r.name IN ('Admin', 'Registrar')
    )
"""

DROP_OLD_POLICIES_SQL = """
DROP POLICY IF EXISTS exam_answer_keys_staff_all ON exam_answer_keys;
DROP POLICY IF EXISTS exam_answer_keys_service_all ON exam_answer_keys;
DROP POLICY IF EXISTS grades_delete ON grades;
DROP POLICY IF EXISTS grades_update ON grades;
DROP POLICY IF EXISTS grades_insert ON grades;
DROP POLICY IF EXISTS grades_select ON grades;
DROP POLICY IF EXISTS grades_service_all ON grades;
DROP POLICY IF EXISTS grade_history_insert ON grade_history;
DROP POLICY IF EXISTS grade_history_select ON grade_history;
DROP POLICY IF EXISTS grade_history_service_all ON grade_history;
DROP POLICY IF EXISTS assessment_attempts_delete ON assessment_attempts;
DROP POLICY IF EXISTS assessment_attempts_update ON assessment_attempts;
DROP POLICY IF EXISTS assessment_attempts_insert ON assessment_attempts;
DROP POLICY IF EXISTS assessment_attempts_select ON assessment_attempts;
DROP POLICY IF EXISTS assessment_attempts_service_all ON assessment_attempts;
"""

# Copy each assessment's and attendance session's course from the module it used to sit in.
# SET CONSTRAINTS ALL IMMEDIATE fires the deferred foreign key checks now, so the table changes that follow are allowed in the same transaction.
BACKFILL_COURSE_SQL = """
UPDATE assessments a
SET course_id = m.course_id
FROM module_sections ms
JOIN modules m ON m.id = ms.module_id
WHERE ms.id = a.section_id;

UPDATE module_attendance_sessions s
SET course_id = m.course_id
FROM modules m
WHERE m.id = s.module_id;

SET CONSTRAINTS ALL IMMEDIATE;
"""

# Same rules as migration 0026, with the course read straight from assessments.course_id.
NEW_POLICIES_SQL = f"""
CREATE POLICY grades_service_all ON grades
    AS PERMISSIVE FOR ALL
    USING (current_setting('kura.service_role', true) = 'management_command')
    WITH CHECK (current_setting('kura.service_role', true) = 'management_command');

CREATE POLICY grades_select ON grades
    AS PERMISSIVE FOR SELECT
    USING (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            student_id::text = current_setting('kura.current_user_id', true)
            OR EXISTS (
                SELECT 1 FROM course_staff cs
                JOIN assessments a ON a.id = grades.assessment_id
                WHERE cs.course_id = a.course_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN courses c ON c.id = a.course_id
                JOIN departments d ON d.id = c.department_id
                WHERE a.id = grades.assessment_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    );

CREATE POLICY grades_insert ON grades
    AS PERMISSIVE FOR INSERT
    WITH CHECK (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            (
                student_id::text = current_setting('kura.current_user_id', true)
                AND status = 'draft'
                AND grader_id IS NULL
                AND finalized_by_id IS NULL
                AND finalized_at IS NULL
                AND released_by_id IS NULL
                AND released_at IS NULL
            )
            OR (
                status = 'draft'
                AND finalized_by_id IS NULL
                AND finalized_at IS NULL
                AND released_by_id IS NULL
                AND released_at IS NULL
                AND EXISTS (
                    SELECT 1 FROM course_staff cs
                    JOIN assessments a ON a.id = grades.assessment_id
                    WHERE cs.course_id = a.course_id
                    AND cs.user_id::text = current_setting('kura.current_user_id', true)
                    AND cs.staff_role = 'teaching_assistant'
                )
            )
            OR EXISTS (
                SELECT 1 FROM course_staff cs
                JOIN assessments a ON a.id = grades.assessment_id
                WHERE cs.course_id = a.course_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor')
            )
        )
    );

CREATE POLICY grades_update ON grades
    AS PERMISSIVE FOR UPDATE
    USING (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            EXISTS (
                SELECT 1 FROM course_staff cs
                JOIN assessments a ON a.id = grades.assessment_id
                WHERE cs.course_id = a.course_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN courses c ON c.id = a.course_id
                JOIN departments d ON d.id = c.department_id
                WHERE a.id = grades.assessment_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    )
    WITH CHECK (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            (
                status = 'draft'
                AND finalized_by_id IS NULL
                AND finalized_at IS NULL
                AND released_by_id IS NULL
                AND released_at IS NULL
                AND EXISTS (
                    SELECT 1 FROM course_staff cs
                    JOIN assessments a ON a.id = grades.assessment_id
                    WHERE cs.course_id = a.course_id
                    AND cs.user_id::text = current_setting('kura.current_user_id', true)
                    AND cs.staff_role = 'teaching_assistant'
                )
            )
            OR EXISTS (
                SELECT 1 FROM course_staff cs
                JOIN assessments a ON a.id = grades.assessment_id
                WHERE cs.course_id = a.course_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor')
            )
            OR (
                status = 'released'
                AND EXISTS (
                    SELECT 1 FROM assessments a
                    JOIN courses c ON c.id = a.course_id
                    JOIN departments d ON d.id = c.department_id
                    WHERE a.id = grades.assessment_id
                    AND d.head_user_id::text = current_setting('kura.current_user_id', true)
                )
            )
        )
    );

CREATE POLICY grades_delete ON grades
    AS PERMISSIVE FOR DELETE
    USING (false);

CREATE POLICY grade_history_service_all ON grade_history
    AS PERMISSIVE FOR ALL
    USING (current_setting('kura.service_role', true) = 'management_command')
    WITH CHECK (current_setting('kura.service_role', true) = 'management_command');

CREATE POLICY grade_history_select ON grade_history
    AS PERMISSIVE FOR SELECT
    USING (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            EXISTS (
                SELECT 1 FROM grades g
                JOIN assessments a ON a.id = g.assessment_id
                JOIN course_staff cs ON cs.course_id = a.course_id
                WHERE g.id = grade_history.grade_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM grades g
                JOIN assessments a ON a.id = g.assessment_id
                JOIN courses c ON c.id = a.course_id
                JOIN departments d ON d.id = c.department_id
                WHERE g.id = grade_history.grade_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    );

CREATE POLICY grade_history_insert ON grade_history
    AS PERMISSIVE FOR INSERT
    WITH CHECK (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            (
                old_status IS NULL
                AND new_status = 'draft'
                AND approved_by_id IS NULL
                AND changed_by_id::text = current_setting('kura.current_user_id', true)
                AND EXISTS (
                    SELECT 1 FROM grades g
                    WHERE g.id = grade_history.grade_id
                    AND g.student_id::text = current_setting('kura.current_user_id', true)
                )
            )
            OR (
                (old_status IS NULL OR old_status = 'draft')
                AND new_status = 'draft'
                AND approved_by_id IS NULL
                AND EXISTS (
                    SELECT 1 FROM grades g
                    JOIN assessments a ON a.id = g.assessment_id
                    JOIN course_staff cs ON cs.course_id = a.course_id
                    WHERE g.id = grade_history.grade_id
                    AND cs.user_id::text = current_setting('kura.current_user_id', true)
                    AND cs.staff_role = 'teaching_assistant'
                )
            )
            OR EXISTS (
                SELECT 1 FROM grades g
                JOIN assessments a ON a.id = g.assessment_id
                JOIN course_staff cs ON cs.course_id = a.course_id
                WHERE g.id = grade_history.grade_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor')
            )
            OR (
                old_status = 'released'
                AND new_status = 'released'
                AND approved_by_id::text = current_setting('kura.current_user_id', true)
                AND EXISTS (
                    SELECT 1 FROM grades g
                    JOIN assessments a ON a.id = g.assessment_id
                    JOIN courses c ON c.id = a.course_id
                    JOIN departments d ON d.id = c.department_id
                    WHERE g.id = grade_history.grade_id
                    AND d.head_user_id::text = current_setting('kura.current_user_id', true)
                )
            )
        )
    );

CREATE POLICY assessment_attempts_service_all ON assessment_attempts
    AS PERMISSIVE FOR ALL
    USING (current_setting('kura.service_role', true) = 'management_command')
    WITH CHECK (current_setting('kura.service_role', true) = 'management_command');

CREATE POLICY assessment_attempts_select ON assessment_attempts
    AS PERMISSIVE FOR SELECT
    USING (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            student_id::text = current_setting('kura.current_user_id', true)
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN course_staff cs ON cs.course_id = a.course_id
                WHERE a.id = assessment_attempts.assessment_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN courses c ON c.id = a.course_id
                JOIN departments d ON d.id = c.department_id
                WHERE a.id = assessment_attempts.assessment_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    );

CREATE POLICY assessment_attempts_insert ON assessment_attempts
    AS PERMISSIVE FOR INSERT
    WITH CHECK (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            student_id::text = current_setting('kura.current_user_id', true)
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN course_staff cs ON cs.course_id = a.course_id
                WHERE a.id = assessment_attempts.assessment_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN courses c ON c.id = a.course_id
                JOIN departments d ON d.id = c.department_id
                WHERE a.id = assessment_attempts.assessment_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    );

CREATE POLICY assessment_attempts_update ON assessment_attempts
    AS PERMISSIVE FOR UPDATE
    USING (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            student_id::text = current_setting('kura.current_user_id', true)
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN course_staff cs ON cs.course_id = a.course_id
                WHERE a.id = assessment_attempts.assessment_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN courses c ON c.id = a.course_id
                JOIN departments d ON d.id = c.department_id
                WHERE a.id = assessment_attempts.assessment_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    )
    WITH CHECK (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            student_id::text = current_setting('kura.current_user_id', true)
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN course_staff cs ON cs.course_id = a.course_id
                WHERE a.id = assessment_attempts.assessment_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN courses c ON c.id = a.course_id
                JOIN departments d ON d.id = c.department_id
                WHERE a.id = assessment_attempts.assessment_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    );

CREATE POLICY assessment_attempts_delete ON assessment_attempts
    AS PERMISSIVE FOR DELETE
    USING (false);
"""


class Migration(migrations.Migration):
    dependencies = [
        ("kura", "0028_security_policy_and_gdpr_fields"),
    ]

    operations = [
        migrations.RunSQL(DROP_OLD_POLICIES_SQL, migrations.RunSQL.noop),
        # Grade appeals, grade weighting, and the content tree.
        migrations.RemoveField(model_name="gradechangerequest", name="appeal"),
        migrations.DeleteModel(name="GradeAppeal"),
        migrations.DeleteModel(name="ExamAnswerKey"),
        migrations.DeleteModel(name="CourseGradeScheme"),
        migrations.DeleteModel(name="SectionItemFile"),
        migrations.DeleteModel(name="SectionItem"),
        migrations.DeleteModel(name="ModuleTargetLevel"),
        # Assessments and attendance sessions move from modules to courses.
        migrations.AddField(
            model_name="assessment",
            name="course",
            field=models.ForeignKey(
                null=True, on_delete=django.db.models.deletion.CASCADE, related_name="assessments", to="kura.course"
            ),
        ),
        migrations.AddField(
            model_name="moduleattendancesession",
            name="course",
            field=models.ForeignKey(
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="attendance_sessions",
                to="kura.course",
            ),
        ),
        migrations.RunSQL(BACKFILL_COURSE_SQL, migrations.RunSQL.noop),
        migrations.AlterField(
            model_name="assessment",
            name="course",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE, related_name="assessments", to="kura.course"
            ),
        ),
        migrations.AlterField(
            model_name="moduleattendancesession",
            name="course",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="attendance_sessions",
                to="kura.course",
            ),
        ),
        migrations.RemoveField(model_name="assessment", name="section"),
        migrations.RemoveField(model_name="moduleattendancesession", name="module"),
        migrations.DeleteModel(name="ModuleSection"),
        migrations.DeleteModel(name="Module"),
        # Online exam fields.
        migrations.RemoveConstraint(model_name="assessment", name="assessment_duration_positive"),
        migrations.RemoveField(model_name="assessment", name="delivery_mode"),
        migrations.RemoveField(model_name="assessment", name="duration_minutes"),
        migrations.RemoveField(model_name="assessment", name="lab_cidr_allowed"),
        migrations.RemoveField(model_name="assessment", name="proctor_code_hash"),
        migrations.RemoveField(model_name="assessment", name="settings_json"),
        migrations.RemoveField(model_name="assessment", name="questions_json"),
        migrations.RemoveField(model_name="assessmentattempt", name="expires_at"),
        migrations.RemoveField(model_name="assessmentattempt", name="last_autosave_at"),
        migrations.RemoveField(model_name="assessmentattempt", name="answers_json"),
        migrations.RemoveField(model_name="assessmentattempt", name="summary_score_json"),
        migrations.RemoveField(model_name="assessmentattempt", name="tab_focus_lost_count"),
        # Flat list of course materials.
        migrations.CreateModel(
            name="CourseFile",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("title", models.CharField(max_length=255)),
                ("is_visible", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "course",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, related_name="course_files", to="kura.course"
                    ),
                ),
                (
                    "file",
                    models.OneToOneField(
                        db_column="file_id",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="course_attachment",
                        to="kura.storedfile",
                    ),
                ),
            ],
            options={"db_table": "course_files"},
        ),
        migrations.RunSQL(NEW_POLICIES_SQL, migrations.RunSQL.noop),
    ]
