from django.db import migrations


NOT_ADMIN_OR_REGISTRAR = """
    NOT EXISTS (
        SELECT 1 FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id::text = current_setting('kura.current_user_id', true)
        AND r.name IN ('Admin', 'Registrar')
    )
"""

FORWARD_SQL = f"""
-- 1. W4: Restrict kura_readonly from reading sensitive binary, key, token, and MFA secret columns.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kura_readonly') THEN
        REVOKE SELECT ON file_contents, exam_answer_keys, password_reset_tokens FROM kura_readonly;
        REVOKE SELECT ON users FROM kura_readonly;
        GRANT SELECT (
            id, email, password_hash, first_name, last_name, mfa_enabled, is_active,
            must_change_password, locked_until, last_login_at, password_changed_at,
            deactivated_at, created_by_id, created_at, updated_at
        ) ON users TO kura_readonly;
    END IF;
END
$$;

-- 2. W5: Narrow grades RLS by staff_role and exclude Admin/Registrar even with stale links.
DROP POLICY IF EXISTS grade_isolation_policy ON grades;

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
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                WHERE cs.course_id = m.course_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
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
                    JOIN module_sections ms ON ms.id = a.section_id
                    JOIN modules m ON m.id = ms.module_id
                    WHERE cs.course_id = m.course_id
                    AND cs.user_id::text = current_setting('kura.current_user_id', true)
                    AND cs.staff_role = 'teaching_assistant'
                )
            )
            OR EXISTS (
                SELECT 1 FROM course_staff cs
                JOIN assessments a ON a.id = grades.assessment_id
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                WHERE cs.course_id = m.course_id
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
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                WHERE cs.course_id = m.course_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
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
                    JOIN module_sections ms ON ms.id = a.section_id
                    JOIN modules m ON m.id = ms.module_id
                    WHERE cs.course_id = m.course_id
                    AND cs.user_id::text = current_setting('kura.current_user_id', true)
                    AND cs.staff_role = 'teaching_assistant'
                )
            )
            OR EXISTS (
                SELECT 1 FROM course_staff cs
                JOIN assessments a ON a.id = grades.assessment_id
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                WHERE cs.course_id = m.course_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor')
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
        )
    );

CREATE POLICY grades_delete ON grades
    AS PERMISSIVE FOR DELETE
    USING (false);

-- 3. W5: Enable and force RLS on course_results.
ALTER TABLE course_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE course_results FORCE ROW LEVEL SECURITY;

CREATE POLICY course_results_service_all ON course_results
    AS PERMISSIVE FOR ALL
    USING (current_setting('kura.service_role', true) = 'management_command')
    WITH CHECK (current_setting('kura.service_role', true) = 'management_command');

CREATE POLICY course_results_select ON course_results
    AS PERMISSIVE FOR SELECT
    USING (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            (student_id::text = current_setting('kura.current_user_id', true) AND status = 'released')
            OR EXISTS (
                SELECT 1 FROM course_staff cs
                WHERE cs.course_id = course_results.course_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM courses c
                JOIN departments d ON d.id = c.department_id
                WHERE c.id = course_results.course_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    );

CREATE POLICY course_results_insert ON course_results
    AS PERMISSIVE FOR INSERT
    WITH CHECK (
        {NOT_ADMIN_OR_REGISTRAR}
        AND EXISTS (
            SELECT 1 FROM course_staff cs
            WHERE cs.course_id = course_results.course_id
            AND cs.user_id::text = current_setting('kura.current_user_id', true)
            AND cs.staff_role IN ('lead_instructor', 'co_instructor')
        )
    );

CREATE POLICY course_results_update ON course_results
    AS PERMISSIVE FOR UPDATE
    USING (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            EXISTS (
                SELECT 1 FROM course_staff cs
                WHERE cs.course_id = course_results.course_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor')
            )
            OR EXISTS (
                SELECT 1 FROM courses c
                JOIN departments d ON d.id = c.department_id
                WHERE c.id = course_results.course_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    )
    WITH CHECK (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            EXISTS (
                SELECT 1 FROM course_staff cs
                WHERE cs.course_id = course_results.course_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor')
            )
            OR EXISTS (
                SELECT 1 FROM courses c
                JOIN departments d ON d.id = c.department_id
                WHERE c.id = course_results.course_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    );

CREATE POLICY course_results_delete ON course_results
    AS PERMISSIVE FOR DELETE
    USING (false);

-- 4. W5: Enable and force RLS on grade_history.
ALTER TABLE grade_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE grade_history FORCE ROW LEVEL SECURITY;

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
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN course_staff cs ON cs.course_id = m.course_id
                WHERE g.id = grade_history.grade_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM grades g
                JOIN assessments a ON a.id = g.assessment_id
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN courses c ON c.id = m.course_id
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
                    JOIN module_sections ms ON ms.id = a.section_id
                    JOIN modules m ON m.id = ms.module_id
                    JOIN course_staff cs ON cs.course_id = m.course_id
                    WHERE g.id = grade_history.grade_id
                    AND cs.user_id::text = current_setting('kura.current_user_id', true)
                    AND cs.staff_role = 'teaching_assistant'
                )
            )
            OR EXISTS (
                SELECT 1 FROM grades g
                JOIN assessments a ON a.id = g.assessment_id
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN course_staff cs ON cs.course_id = m.course_id
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
                    JOIN module_sections ms ON ms.id = a.section_id
                    JOIN modules m ON m.id = ms.module_id
                    JOIN courses c ON c.id = m.course_id
                    JOIN departments d ON d.id = c.department_id
                    WHERE g.id = grade_history.grade_id
                    AND d.head_user_id::text = current_setting('kura.current_user_id', true)
                )
            )
        )
    );

-- 5. W5: Enable and force RLS on assessment_attempts.
ALTER TABLE assessment_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE assessment_attempts FORCE ROW LEVEL SECURITY;

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
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN course_staff cs ON cs.course_id = m.course_id
                WHERE a.id = assessment_attempts.assessment_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN courses c ON c.id = m.course_id
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
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN course_staff cs ON cs.course_id = m.course_id
                WHERE a.id = assessment_attempts.assessment_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN courses c ON c.id = m.course_id
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
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN course_staff cs ON cs.course_id = m.course_id
                WHERE a.id = assessment_attempts.assessment_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN courses c ON c.id = m.course_id
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
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN course_staff cs ON cs.course_id = m.course_id
                WHERE a.id = assessment_attempts.assessment_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor', 'teaching_assistant')
            )
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN courses c ON c.id = m.course_id
                JOIN departments d ON d.id = c.department_id
                WHERE a.id = assessment_attempts.assessment_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    );

CREATE POLICY assessment_attempts_delete ON assessment_attempts
    AS PERMISSIVE FOR DELETE
    USING (false);

-- 6. W5: Enable and force RLS on exam_answer_keys (instructors and department heads only).
ALTER TABLE exam_answer_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE exam_answer_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY exam_answer_keys_service_all ON exam_answer_keys
    AS PERMISSIVE FOR ALL
    USING (current_setting('kura.service_role', true) = 'management_command')
    WITH CHECK (current_setting('kura.service_role', true) = 'management_command');

CREATE POLICY exam_answer_keys_staff_all ON exam_answer_keys
    AS PERMISSIVE FOR ALL
    USING (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            EXISTS (
                SELECT 1 FROM assessments a
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN course_staff cs ON cs.course_id = m.course_id
                WHERE a.id = exam_answer_keys.assessment_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor')
            )
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN courses c ON c.id = m.course_id
                JOIN departments d ON d.id = c.department_id
                WHERE a.id = exam_answer_keys.assessment_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    )
    WITH CHECK (
        {NOT_ADMIN_OR_REGISTRAR}
        AND (
            EXISTS (
                SELECT 1 FROM assessments a
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN course_staff cs ON cs.course_id = m.course_id
                WHERE a.id = exam_answer_keys.assessment_id
                AND cs.user_id::text = current_setting('kura.current_user_id', true)
                AND cs.staff_role IN ('lead_instructor', 'co_instructor')
            )
            OR EXISTS (
                SELECT 1 FROM assessments a
                JOIN module_sections ms ON ms.id = a.section_id
                JOIN modules m ON m.id = ms.module_id
                JOIN courses c ON c.id = m.course_id
                JOIN departments d ON d.id = c.department_id
                WHERE a.id = exam_answer_keys.assessment_id
                AND d.head_user_id::text = current_setting('kura.current_user_id', true)
            )
        )
    );
"""

REVERSE_SQL = """
DROP POLICY IF EXISTS exam_answer_keys_staff_all ON exam_answer_keys;
DROP POLICY IF EXISTS exam_answer_keys_service_all ON exam_answer_keys;
ALTER TABLE exam_answer_keys NO FORCE ROW LEVEL SECURITY;
ALTER TABLE exam_answer_keys DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS assessment_attempts_delete ON assessment_attempts;
DROP POLICY IF EXISTS assessment_attempts_update ON assessment_attempts;
DROP POLICY IF EXISTS assessment_attempts_insert ON assessment_attempts;
DROP POLICY IF EXISTS assessment_attempts_select ON assessment_attempts;
DROP POLICY IF EXISTS assessment_attempts_service_all ON assessment_attempts;
ALTER TABLE assessment_attempts NO FORCE ROW LEVEL SECURITY;
ALTER TABLE assessment_attempts DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS grade_history_insert ON grade_history;
DROP POLICY IF EXISTS grade_history_select ON grade_history;
DROP POLICY IF EXISTS grade_history_service_all ON grade_history;
ALTER TABLE grade_history NO FORCE ROW LEVEL SECURITY;
ALTER TABLE grade_history DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS course_results_delete ON course_results;
DROP POLICY IF EXISTS course_results_update ON course_results;
DROP POLICY IF EXISTS course_results_insert ON course_results;
DROP POLICY IF EXISTS course_results_select ON course_results;
DROP POLICY IF EXISTS course_results_service_all ON course_results;
ALTER TABLE course_results NO FORCE ROW LEVEL SECURITY;
ALTER TABLE course_results DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS grades_delete ON grades;
DROP POLICY IF EXISTS grades_update ON grades;
DROP POLICY IF EXISTS grades_insert ON grades;
DROP POLICY IF EXISTS grades_select ON grades;
DROP POLICY IF EXISTS grades_service_all ON grades;

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

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kura_readonly') THEN
        GRANT SELECT ON file_contents, exam_answer_keys, password_reset_tokens, users TO kura_readonly;
    END IF;
END
$$;
"""


class Migration(migrations.Migration):
    dependencies = [
        ("kura", "0025_submission_hash_immutability_trigger"),
    ]

    operations = [
        migrations.RunSQL(sql=FORWARD_SQL, reverse_sql=REVERSE_SQL),
    ]
