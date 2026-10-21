"""Student-specific MCP tools for Canvas API.

These tools provide student-focused functionality using Canvas API "/self" endpoints
to access only the student's own data across their enrolled courses.
"""

from datetime import datetime, timedelta, timezone

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..core.cache import get_course_code, get_course_id
from ..core.client import fetch_all_paginated_results, make_canvas_request
from ..core.dates import format_date, parse_date
from ..core.validation import validate_params


def _format_rubric_assessment(assessment: dict | None, rubric: list | None) -> list[str]:
    """Format a rubric_assessment dict, labelled with the assignment's rubric when available."""
    if not assessment:
        return ["  Rubric: No rubric assessment"]

    criteria = {c.get("id"): c for c in rubric or [] if isinstance(c, dict)}
    order = [c.get("id") for c in rubric or [] if isinstance(c, dict) and c.get("id") in assessment]
    order += [cid for cid in assessment if cid not in order]

    lines = ["  Rubric:"]
    for criterion_id in order:
        result = assessment.get(criterion_id) or {}
        criterion = criteria.get(criterion_id, {})
        label = criterion.get("description") or f"Criterion {criterion_id}"
        points = result.get("points")
        possible = criterion.get("points")
        score = "no score" if points is None else (f"{points} / {possible}" if possible is not None else f"{points}")
        rating = next(
            (r.get("description") for r in criterion.get("ratings") or [] if r.get("id") == result.get("rating_id")),
            None,
        )
        lines.append(f"    - {label}: {score}" + (f" ({rating})" if rating else ""))
        if result.get("comments"):
            lines.append(f"      Comment: {result['comments'].strip()}")
    return lines


def register_student_tools(mcp: FastMCP):
    """Register student-specific MCP tools."""

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    @validate_params
    async def get_my_upcoming_assignments(days: int = 7) -> str:
        """Get your upcoming assignments across all courses.

        Args:
            days: Number of days to look ahead (default: 7)
        """
        # Calculate the date range (use timezone-aware datetime)
        end_date = datetime.now(timezone.utc) + timedelta(days=days)

        # Get upcoming events for the current user
        events = await fetch_all_paginated_results(
            "/users/self/upcoming_events",
            params={"per_page": 100}
        )

        if isinstance(events, dict) and "error" in events:
            return f"Error fetching upcoming assignments: {events['error']}"

        if not events:
            return f"No assignments due in the next {days} days."

        # Filter to assignments only (not calendar events)
        assignments = []
        for event in events:
            if event.get("type") == "assignment" or event.get("assignment"):
                assignment_data = event.get("assignment", event)
                due_at = assignment_data.get("due_at")

                if due_at:
                    # Check if within our date range
                    due_date = parse_date(due_at)
                    if due_date and due_date <= end_date:
                        assignments.append(assignment_data)

        if not assignments:
            return f"No assignments due in the next {days} days."

        # Sort by due date (use timezone-aware max for fallback)
        assignments.sort(key=lambda x: parse_date(x.get("due_at", "")) or datetime.max.replace(tzinfo=timezone.utc))

        # Format output
        output_lines = [f"Upcoming Assignments (Next {days} Days):\n"]

        for assignment in assignments:
            name = assignment.get("name", "Unnamed Assignment")
            due_at = format_date(assignment.get("due_at"))
            course_id = assignment.get("course_id")

            # Get course name
            course_display = await get_course_code(course_id) if course_id else "Unknown Course"

            assignment_id = assignment.get("id")
            if course_id and assignment_id:
                sub = await make_canvas_request(
                    "get",
                    f"/courses/{course_id}/assignments/{assignment_id}/submissions/self"
                )
                if isinstance(sub, dict) and sub.get("submitted_at"):
                    status = "✅ Submitted"
                else:
                    status = "❌ Not Submitted"
            else:
                status = "❌ Not Submitted"

            output_lines.append(
                f"• {name}\n"
                f"  Course: {course_display}\n"
                f"  Due: {due_at}\n"
                f"  Status: {status}\n"
            )

        return "\n".join(output_lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    @validate_params
    async def get_my_submission_status(course_identifier: str | int | None = None) -> str:
        """Get your submission status for assignments.

        Args:
            course_identifier: Course code or Canvas ID (omit for all courses)
        """
        if course_identifier:
            # Get submissions for specific course
            course_id = await get_course_id(course_identifier)

            assignments = await fetch_all_paginated_results(
                f"/courses/{course_id}/assignments",
                params={"include[]": ["submission"], "per_page": 100}
            )

            if isinstance(assignments, dict) and "error" in assignments:
                return f"Error fetching assignments: {assignments['error']}"

            course_display = await get_course_code(course_id) or course_identifier
            output_lines = [f"Submission Status for {course_display}:\n"]

        else:
            # Get all courses and their assignments
            courses = await fetch_all_paginated_results(
                "/courses",
                params={"enrollment_state": "active", "per_page": 100}
            )

            if isinstance(courses, dict) and "error" in courses:
                return f"Error fetching courses: {courses['error']}"

            output_lines = ["Submission Status (All Courses):\n"]
            all_assignments = []

            for course in courses:
                course_id = course.get("id")
                course_name = course.get("course_code", course.get("name", "Unknown"))

                assignments = await fetch_all_paginated_results(
                    f"/courses/{course_id}/assignments",
                    params={"include[]": ["submission"], "per_page": 100}
                )

                if not isinstance(assignments, dict) or "error" not in assignments:
                    for assignment in assignments if isinstance(assignments, list) else []:
                        assignment["_course_name"] = course_name
                        all_assignments.append(assignment)

            assignments = all_assignments

        if not assignments:
            return "No assignments found."

        # Separate submitted and missing
        submitted = []
        missing = []

        for assignment in assignments:
            submission = assignment.get("submission")
            is_submitted = submission and submission.get("submitted_at") is not None

            if is_submitted:
                submitted.append(assignment)
            else:
                # Check if past due (use timezone-aware datetime)
                due_at = assignment.get("due_at")
                if due_at:
                    due_date = parse_date(due_at)
                    if due_date and due_date < datetime.now(timezone.utc):
                        missing.append((assignment, "OVERDUE"))
                    else:
                        missing.append((assignment, "NOT SUBMITTED"))
                else:
                    missing.append((assignment, "NOT SUBMITTED"))

        # Format output
        if missing:
            output_lines.append(f"⚠️  Missing Submissions ({len(missing)}):\n")
            for assignment, status in missing:
                name = assignment.get("name", "Unnamed")
                due_at = format_date(assignment.get("due_at")) if assignment.get("due_at") else "No due date"
                course_name = assignment.get("_course_name", "")

                output_lines.append(
                    f"• {name}\n"
                    f"  {f'Course: {course_name}' if course_name else ''}\n"
                    f"  Due: {due_at}\n"
                    f"  Status: {status}\n"
                )

        if submitted:
            output_lines.append(f"\n✅ Submitted ({len(submitted)}):\n")
            for assignment in submitted[:10]:  # Show first 10
                name = assignment.get("name", "Unnamed")
                submission = assignment.get("submission", {})
                submitted_at = format_date(submission.get("submitted_at"))
                course_name = assignment.get("_course_name", "")

                output_lines.append(
                    f"• {name}\n"
                    f"  {f'Course: {course_name}' if course_name else ''}\n"
                    f"  Submitted: {submitted_at}\n"
                )

        return "\n".join(output_lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    @validate_params
    async def get_my_submissions(
        course_identifier: str | int,
        assignment_ids: list[str | int] | None = None,
        include_comments: bool = True,
        include_rubric: bool = True,
    ) -> str:
        """Get your own submissions in a course with grades, instructor comments and rubric feedback.

        Works with a student login (uses student_ids[]=self), unlike list_submissions
        and get_rubric_assessment, which need grading rights.

        Args:
            course_identifier: Course code or Canvas ID
            assignment_ids: Assignment IDs to limit to (omit for every assignment)
            include_comments: Include submission comments (default: True)
            include_rubric: Include rubric assessment scores and comments (default: True)
        """
        course_id = await get_course_id(course_identifier)

        includes = ["assignment"]
        if include_comments:
            includes.append("submission_comments")
        if include_rubric:
            includes.append("rubric_assessment")

        params: dict = {"student_ids[]": ["self"], "include[]": includes, "per_page": 100}
        if assignment_ids:
            params["assignment_ids[]"] = [str(a) for a in assignment_ids]

        submissions = await fetch_all_paginated_results(
            f"/courses/{course_id}/students/submissions", params
        )

        if isinstance(submissions, dict) and "error" in submissions:
            return f"Error fetching your submissions: {submissions['error']}"

        course_display = await get_course_code(course_id) or course_identifier

        if not submissions:
            return f"No submissions found for you in {course_display}."

        submissions = sorted(
            submissions,
            key=lambda s: parse_date((s.get("assignment") or {}).get("due_at"))
            or datetime.max.replace(tzinfo=timezone.utc),
        )

        if include_rubric:
            # Label rubric scores with criterion names when the embedded assignment lacks its rubric
            for submission in submissions:
                assignment = submission.get("assignment") or {}
                if submission.get("rubric_assessment") and not assignment.get("rubric"):
                    details = await make_canvas_request(
                        "get", f"/courses/{course_id}/assignments/{submission.get('assignment_id')}"
                    )
                    if isinstance(details, dict) and "error" not in details:
                        submission["assignment"] = {**details, **assignment, "rubric": details.get("rubric")}

        output_lines = [f"Your Submissions in {course_display}:\n"]

        for submission in submissions:
            assignment = submission.get("assignment") or {}
            name = assignment.get("name") or f"Assignment {submission.get('assignment_id')}"
            points_possible = assignment.get("points_possible")

            lines = [f"• {name} (assignment {submission.get('assignment_id')})"]
            if assignment.get("due_at"):
                lines.append(f"  Due: {format_date(assignment.get('due_at'))}")

            if submission.get("submitted_at"):
                lines.append(f"  Submitted: {format_date(submission.get('submitted_at'))}")
            else:
                lines.append("  Submitted: Not submitted")

            flags = [flag for flag in ("late", "missing", "excused") if submission.get(flag)]
            state = submission.get("workflow_state", "unknown")
            lines.append(f"  Status: {state}" + (f" ({', '.join(flags)})" if flags else ""))

            score = submission.get("score")
            if score is not None:
                out_of = f" / {points_possible}" if points_possible is not None else ""
                grade = submission.get("grade")
                grade_text = f" (grade: {grade})" if grade not in (None, "", str(score)) else ""
                lines.append(f"  Score: {score}{out_of}{grade_text}")
            else:
                lines.append("  Score: Not graded or not posted yet")

            if include_rubric:
                lines.extend(_format_rubric_assessment(
                    submission.get("rubric_assessment"), assignment.get("rubric")
                ))

            if include_comments:
                comments = submission.get("submission_comments") or []
                if comments:
                    lines.append(f"  Comments ({len(comments)}):")
                    for comment in sorted(comments, key=lambda c: c.get("created_at") or ""):
                        author = comment.get("author_name") or "Unknown"
                        when = format_date(comment.get("created_at"))
                        text = (comment.get("comment") or "").strip()
                        lines.append(f"    - {author} ({when}): {text}")
                        for attachment in comment.get("attachments") or []:
                            label = attachment.get("display_name") or attachment.get("filename") or "file"
                            lines.append(f"      Attachment: {label} {attachment.get('url', '')}".rstrip())
                else:
                    lines.append("  Comments: None")

            output_lines.append("\n".join(lines) + "\n")

        return "\n".join(output_lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def get_my_course_grades() -> str:
        """Get your current grades across all enrolled courses."""
        courses = await fetch_all_paginated_results(
            "/courses",
            params={
                "enrollment_state": "active",
                "include[]": ["total_scores", "current_grading_period_scores"],
                "per_page": 100
            }
        )

        if isinstance(courses, dict) and "error" in courses:
            return f"Error fetching courses: {courses['error']}"

        if not courses:
            return "No active course enrollments found."

        output_lines = ["Your Course Grades:\n"]

        for course in courses:
            name = course.get("name", "Unnamed Course")
            course_code = course.get("course_code", "")

            # Get enrollment data (grades)
            enrollments = course.get("enrollments", [])
            if enrollments:
                enrollment = enrollments[0]  # Student typically has one enrollment per course

                # Current score
                current_score = enrollment.get("computed_current_score")
                final_score = enrollment.get("computed_final_score")
                current_grade = enrollment.get("computed_current_grade", "N/A")

                # Format grade info
                if current_score is not None:
                    grade_info = f"{current_grade} ({current_score:.1f}%)"
                elif final_score is not None:
                    grade_info = f"{final_score:.1f}%"
                else:
                    grade_info = "No grade yet"

                output_lines.append(
                    f"• {course_code}: {name}\n"
                    f"  Current Grade: {grade_info}\n"
                )
            else:
                output_lines.append(
                    f"• {course_code}: {name}\n"
                    f"  Current Grade: No enrollment data\n"
                )

        return "\n".join(output_lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def get_my_todo_items() -> str:
        """Get your Canvas TODO list."""
        todos = await fetch_all_paginated_results(
            "/users/self/todo",
            params={"per_page": 100}
        )

        if isinstance(todos, dict) and "error" in todos:
            return f"Error fetching TODO items: {todos['error']}"

        if not todos:
            return "Your TODO list is empty! 🎉"

        output_lines = ["Your TODO List:\n"]

        for item in todos:
            item_type = item.get("type", "item")
            assignment = item.get("assignment", {})

            name = assignment.get("name") or item.get("title", "Unnamed item")
            due_at = format_date(assignment.get("due_at")) if assignment.get("due_at") else "No due date"
            course_id = item.get("course_id")

            course_display = await get_course_code(course_id) if course_id else "Unknown Course"

            output_lines.append(
                f"• {name}\n"
                f"  Type: {item_type.title()}\n"
                f"  Course: {course_display}\n"
                f"  Due: {due_at}\n"
            )

        return "\n".join(output_lines)

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    @validate_params
    async def get_my_peer_reviews_todo(course_identifier: str | int | None = None) -> str:
        """Get peer reviews you need to complete.

        Args:
            course_identifier: Course code or Canvas ID (omit for all courses)
        """
        if course_identifier:
            course_ids = [await get_course_id(course_identifier)]
        else:
            # Get all active courses
            courses = await fetch_all_paginated_results(
                "/courses",
                params={"enrollment_state": "active", "per_page": 100}
            )
            if isinstance(courses, dict) and "error" in courses:
                return f"Error fetching courses: {courses['error']}"

            course_ids = [course.get("id") for course in courses if course.get("id")]

        all_peer_reviews = []

        for course_id in course_ids:
            # Get assignments for this course
            assignments = await fetch_all_paginated_results(
                f"/courses/{course_id}/assignments",
                params={"per_page": 100}
            )

            if isinstance(assignments, dict) and "error" in assignments:
                continue

            # Check each assignment for peer reviews
            for assignment in assignments if isinstance(assignments, list) else []:
                if assignment.get("peer_reviews"):
                    assignment_id = assignment.get("id")

                    # Get peer reviews for this assignment
                    peer_reviews = await fetch_all_paginated_results(
                        f"/courses/{course_id}/assignments/{assignment_id}/peer_reviews",
                        params={"include[]": ["user"], "per_page": 100}
                    )

                    if isinstance(peer_reviews, list):
                        # Filter to reviews assigned to current user that are incomplete
                        for review in peer_reviews:
                            # Note: We'd need to filter by current user ID
                            # For now, show all incomplete reviews
                            if review.get("workflow_state") != "completed":
                                review["_course_id"] = course_id
                                review["_assignment_name"] = assignment.get("name")
                                all_peer_reviews.append(review)

        if not all_peer_reviews:
            return "You have no pending peer reviews! ✅"

        output_lines = ["Peer Reviews You Need to Complete:\n"]

        for review in all_peer_reviews:
            assignment_name = review.get("_assignment_name", "Unknown Assignment")
            course_id = review.get("_course_id")
            course_display = await get_course_code(course_id) if course_id else "Unknown Course"

            user_id = review.get("user_id")
            review.get("assessor_id")

            output_lines.append(
                f"• {assignment_name}\n"
                f"  Course: {course_display}\n"
                f"  Reviewing: Student {user_id}\n"
                f"  Status: Incomplete\n"
            )

        return "\n".join(output_lines)
