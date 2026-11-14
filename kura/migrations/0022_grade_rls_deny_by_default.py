from django.db import migrations


GRADE_ISOLATION_DENY_DEFAULT_SQL = """
DROP POLICY IF EXISTS grade_isolation_policy ON grades;
CREATE POLICY grade_isolation_policy ON grades
    AS PERMISSIVE
    FOR ALL
    USING (
        current_setting('kura.service_role', true) = 'management_command'
        OR student_id::text = current_setting('kura.current_user_id', true)
        OR EXISTS (
            SELECT 1 FROM course_staff cs
            JOIN assessments a ON a.id = grades.assessment_id
            JOIN module_sections ms ON ms.id = a.section_id
            JOIN modules m ON m.id = ms.module_id
            WHERE cs.course_id = m.course_id
            AND cs.user_id::text = current_setting('kura.current_user_id', true)
        )
        OR EXISTS (
            SELECT 1 FROM assessments a
            JOIN module_sections ms ON ms.id = a.section_id
            JOIN modules m ON m.id = ms.module_id
            JOIN courses c ON c.id = m.course_id
            JOIN departments d ON d.id = c.department_id
            WHERE a.id = grades.assessment_id
            AND d.head_user_id::text = current_setting('kura.current_user_id', true)
        )
    )
    WITH CHECK (
        current_setting('kura.service_role', true) = 'management_command'
        OR (
            student_id::text = current_setting('kura.current_user_id', true)
            AND status = 'draft'
            AND grader_id IS NULL
            AND finalized_by_id IS NULL
            AND finalized_at IS NULL
            AND released_by_id IS NULL
            AND released_at IS NULL
        )
        OR EXISTS (
            SELECT 1 FROM course_staff cs
            JOIN assessments a ON a.id = grades.assessment_id
            JOIN module_sections ms ON ms.id = a.section_id
            JOIN modules m ON m.id = ms.module_id
            WHERE cs.course_id = m.course_id
            AND cs.user_id::text = current_setting('kura.current_user_id', true)
        )
        OR (
            status = 'released'
            AND EXISTS (
                SELECT 1 FROM assessments a
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN courses c ON c.id = m.course_id
                JOIN departments d ON d.id = c.department_id
                WHERE a.id = grades.assessment_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    );
"""


PREVIOUS_GRADE_ISOLATION_POLICY_SQL = """
DROP POLICY IF EXISTS grade_isolation_policy ON grades;
CREATE POLICY grade_isolation_policy ON grades
    AS PERMISSIVE
    FOR ALL
    USING (
        current_setting('kura.current_user_id', true) IS NULL
        OR current_setting('kura.current_user_id', true) = ''
        OR student_id::text = current_setting('kura.current_user_id', true)
        OR EXISTS (
            SELECT 1 FROM course_staff cs
            JOIN assessments a ON a.id = grades.assessment_id
            JOIN module_sections ms ON ms.id = a.section_id
            JOIN modules m ON m.id = ms.module_id
            WHERE cs.course_id = m.course_id
            AND cs.user_id::text = current_setting('kura.current_user_id', true)
        )
        OR EXISTS (
            SELECT 1 FROM assessments a
            JOIN module_sections ms ON ms.id = a.section_id
            JOIN modules m ON m.id = ms.module_id
            JOIN courses c ON c.id = m.course_id
            JOIN departments d ON d.id = c.department_id
            WHERE a.id = grades.assessment_id
            AND d.head_user_id::text = current_setting('kura.current_user_id', true)
        )
    )
    WITH CHECK (
        current_setting('kura.current_user_id', true) IS NULL
        OR current_setting('kura.current_user_id', true) = ''
        OR (
            student_id::text = current_setting('kura.current_user_id', true)
            AND status = 'draft'
            AND grader_id IS NULL
            AND finalized_by_id IS NULL
            AND finalized_at IS NULL
            AND released_by_id IS NULL
            AND released_at IS NULL
        )
        OR EXISTS (
            SELECT 1 FROM course_staff cs
            JOIN assessments a ON a.id = grades.assessment_id
            JOIN module_sections ms ON ms.id = a.section_id
            JOIN modules m ON m.id = ms.module_id
            WHERE cs.course_id = m.course_id
            AND cs.user_id::text = current_setting('kura.current_user_id', true)
        )
        OR (
            status = 'released'
            AND EXISTS (
                SELECT 1 FROM assessments a
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN courses c ON c.id = m.course_id
                JOIN departments d ON d.id = c.department_id
                WHERE a.id = grades.assessment_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    );
"""


class Migration(migrations.Migration):
    dependencies = [
        ("kura", "0021_grade_appeal_unique_pending"),
    ]

    operations = [
        migrations.RunSQL(
            sql=GRADE_ISOLATION_DENY_DEFAULT_SQL,
            reverse_sql=PREVIOUS_GRADE_ISOLATION_POLICY_SQL,
        ),
    ]
