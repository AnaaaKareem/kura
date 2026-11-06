from django.db import migrations


RLS_ENABLE_SQL = """
-- 1. Ensure kura_app role exists and has permissions
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kura_app') THEN
        CREATE ROLE kura_app;
    END IF;
END
$$;
GRANT USAGE ON SCHEMA public TO kura_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO kura_app;

-- 2. Enable Row-Level Security on sensitive grade tables
ALTER TABLE grades ENABLE ROW LEVEL SECURITY;
ALTER TABLE grades FORCE ROW LEVEL SECURITY;

-- 3. Define Grade Isolation Policy
-- Students can only select their own grades.
-- Instructors can select grades for courses they teach in CourseStaff.
-- Administrators or background tasks (when kura.current_user_id is unset) can access all rows.
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
    )
    WITH CHECK (
        current_setting('kura.current_user_id', true) IS NULL
        OR current_setting('kura.current_user_id', true) = ''
        OR EXISTS (
            SELECT 1 FROM course_staff cs
            JOIN assessments a ON a.id = grades.assessment_id
            JOIN module_sections ms ON ms.id = a.section_id
            JOIN modules m ON m.id = ms.module_id
            WHERE cs.course_id = m.course_id
            AND cs.user_id::text = current_setting('kura.current_user_id', true)
        )
    );
"""

RLS_REVERSE_SQL = """
DROP POLICY IF EXISTS grade_isolation_policy ON grades;
ALTER TABLE grades DISABLE ROW LEVEL SECURITY;
"""


class Migration(migrations.Migration):

    dependencies = [
        ('kura', '0003_attempt_files_lock_trigger'),
    ]

    operations = [
        migrations.RunSQL(RLS_ENABLE_SQL, RLS_REVERSE_SQL),
    ]
