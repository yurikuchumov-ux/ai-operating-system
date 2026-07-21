"""Regressions for the governed Section 3.1 inventory validator."""

import copy
import json
import unittest
from pathlib import Path

from tools.canonical_repository_plan import (
    SECTION_HEADING,
    TABLE_HEADER,
    TABLE_SEPARATOR,
    validate_execution_plan,
)

_UNSET = object()


class TestCanonicalRepositoryPlan(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.plan = (root / "docs/AI_DEVELOPMENT_STUDIO_EXECUTION_PLAN.md").read_text(
            encoding="utf-8"
        )
        self.registry = json.loads(
            (root / "contracts/canonical-repositories.v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.lines = self.plan.splitlines()
        self.heading = self.lines.index(SECTION_HEADING)
        self.header = self.heading + 2
        self.separator = self.heading + 3
        self.row_start = self.heading + 4
        self.assertEqual(self.lines[self.header], TABLE_HEADER)
        self.assertEqual(self.lines[self.separator], TABLE_SEPARATOR)

    def _with_lines(self, lines):
        return "\n".join(lines) + ("\n" if self.plan.endswith("\n") else "")

    def _replace_line(self, index, replacement):
        lines = self.lines.copy()
        lines[index] = replacement
        return self._with_lines(lines)

    def _delete_line(self, index):
        lines = self.lines.copy()
        del lines[index]
        return self._with_lines(lines)

    def _insert_line(self, index, value):
        lines = self.lines.copy()
        lines.insert(index, value)
        return self._with_lines(lines)

    def _row_cells(self, row=0):
        raw = self.lines[self.row_start + row]
        self.assertTrue(raw.startswith("|") and raw.endswith("|"))
        cells = [cell.strip() for cell in raw[1:-1].split("|")]
        self.assertEqual(len(cells), 5)
        return cells

    def _with_cells(self, row, cells):
        return self._replace_line(
            self.row_start + row, "| " + " | ".join(cells) + " |"
        )

    def _replace_cell_text(self, row, cell, old, new):
        cells = self._row_cells(row)
        self.assertEqual(cells[cell].count(old), 1)
        cells[cell] = cells[cell].replace(old, new, 1)
        return self._with_cells(row, cells)

    def _errors(self, plan=_UNSET, registry=_UNSET):
        return validate_execution_plan(
            self.plan if plan is _UNSET else plan,
            self.registry if registry is _UNSET else registry,
        )

    def test_exact_committed_inputs_pass(self):
        self.assertEqual(self._errors(), [])

    def test_plan_input_invalid(self):
        for value in (None, 1, [], {}):
            with self.subTest(value=value):
                self.assertEqual(self._errors(plan=value), ["plan_input_invalid"])

    def test_registry_input_invalid(self):
        invalid = (
            None,
            [],
            {},
            {"canonical_repositories": {}},
            {"canonical_repositories": [None]},
            {"canonical_repositories": [{"label": "incomplete"}]},
        )
        for value in invalid:
            with self.subTest(value=value):
                self.assertEqual(
                    self._errors(registry=value), ["registry_input_invalid"]
                )

    def test_missing_section(self):
        plan = self._replace_line(self.heading, "### 3.2 Different section")
        self.assertEqual(self._errors(plan), ["plan_section_missing"])

    def test_duplicate_section(self):
        plan = self._insert_line(self.heading + 1, SECTION_HEADING)
        self.assertEqual(self._errors(plan), ["plan_section_duplicate"])

    def test_wrong_heading_levels(self):
        for marker in ("#", "##", "####", "#####", "######"):
            with self.subTest(marker=marker):
                plan = self._replace_line(
                    self.heading, f"{marker} 3.1 Verified names and boundaries"
                )
                self.assertEqual(self._errors(plan), ["plan_section_wrong_level"])

    def test_heading_suffix(self):
        plan = self._replace_line(self.heading, SECTION_HEADING + " changed")
        self.assertEqual(self._errors(plan), ["plan_section_heading_suffix"])

    def test_section_inside_fenced_code_is_not_markdown_heading(self):
        lines = self.lines.copy()
        end = next(
            index
            for index in range(self.heading + 1, len(lines))
            if lines[index].startswith("### ")
        )
        lines.insert(end, "```")
        lines.insert(self.heading, "```markdown")
        self.assertEqual(
            self._errors(self._with_lines(lines)), ["plan_section_missing"]
        )

    def test_section_inside_html_comment_is_not_markdown_heading(self):
        lines = self.lines.copy()
        end = next(
            index
            for index in range(self.heading + 1, len(lines))
            if lines[index].startswith("### ")
        )
        lines.insert(end, "-->")
        lines.insert(self.heading, "<!--")
        self.assertEqual(
            self._errors(self._with_lines(lines)), ["plan_section_missing"]
        )

    def test_header_variants_fail_exactly(self):
        variants = (
            TABLE_HEADER.replace("Role", "Repository role"),
            TABLE_HEADER[:-1] + " Extra |",
            " " + TABLE_HEADER,
            TABLE_HEADER + " ",
        )
        for value in variants:
            with self.subTest(value=value):
                self.assertEqual(
                    self._errors(self._replace_line(self.header, value)),
                    ["plan_header_mismatch"],
                )

    def test_separator_variants_fail_exactly(self):
        variants = (
            TABLE_SEPARATOR.replace("---", ":---", 1),
            TABLE_SEPARATOR[:-1] + " --- |",
            " " + TABLE_SEPARATOR,
            TABLE_SEPARATOR + " ",
        )
        for value in variants:
            with self.subTest(value=value):
                self.assertEqual(
                    self._errors(self._replace_line(self.separator, value)),
                    ["plan_separator_mismatch"],
                )

    def test_missing_and_extra_rows(self):
        self.assertEqual(
            self._errors(self._delete_line(self.row_start + 2)),
            ["plan_row_count_mismatch"],
        )
        self.assertEqual(
            self._errors(
                self._insert_line(self.row_start + 3, self.lines[self.row_start])
            ),
            ["plan_row_count_mismatch"],
        )

    def test_hidden_second_table_fragment_is_extra_row(self):
        # The canonical table is followed by a blank line. A later table row
        # in the same 3.1 section must not be ignored.
        plan = self._insert_line(self.row_start + 4, self.lines[self.row_start])
        self.assertEqual(self._errors(plan), ["plan_row_count_mismatch"])

    def test_indented_hidden_second_table_fragment_is_extra_row(self):
        lines = self.lines.copy()
        insertion = self.row_start + 4
        fragment = [
            " " + TABLE_HEADER,
            " " + TABLE_SEPARATOR,
            " " + self.lines[self.row_start],
        ]
        lines[insertion:insertion] = fragment
        self.assertEqual(
            self._errors(self._with_lines(lines)), ["plan_row_count_mismatch"]
        )

    def test_duplicate_and_substituted_role_rows(self):
        cells = self._row_cells(1)
        cells[0] = self._row_cells(0)[0]
        self.assertEqual(
            self._errors(self._with_cells(1, cells)), ["plan_duplicate_label"]
        )

        cells = self._row_cells(1)
        cells[0] = "Substituted repository role"
        self.assertEqual(
            self._errors(self._with_cells(1, cells)), ["plan_label_set_mismatch"]
        )

    def test_raw_row_column_count_preserves_empty_cells(self):
        cells = self._row_cells(0)
        variants = (
            cells[:-1],
            cells + ["ordinary sixth cell"],
            cells + [""],
            cells + ["[`rogue/repository`](https://github.com/rogue/repository)"],
        )
        for value in variants:
            with self.subTest(value=value):
                self.assertEqual(
                    self._errors(self._with_cells(0, value)),
                    ["plan_row_column_count_mismatch"],
                )

    def test_raw_row_whitespace_is_not_normalized(self):
        row = self.lines[self.row_start]
        self.assertEqual(
            self._errors(self._replace_line(self.row_start, " " + row)),
            ["plan_row_count_mismatch"],
        )
        for value in (row + " ", row.replace(" | ", "  | ", 1)):
            with self.subTest(value=value):
                self.assertEqual(
                    self._errors(self._replace_line(self.row_start, value)),
                    ["plan_row_column_count_mismatch"],
                )

    def test_empty_required_cell_cannot_pass(self):
        cells = self._row_cells(0)
        cells[0] = ""
        self.assertEqual(
            self._errors(self._with_cells(0, cells)), ["plan_label_set_mismatch"]
        )

    def test_unbackticked_rogue_links_are_counted_across_complete_row(self):
        rogue_links = (
            "[rogue](https://github.com/rogue/repository)",
            r"[ro\]gue](https://github.com/rogue/repository)",
            '[rogue](https://github.com/rogue/repository "title")',
            "[outer [nested]](https://github.com/rogue/repository)",
        )
        for rogue in rogue_links:
            for cell in (1, 4):
                with self.subTest(rogue=rogue, cell=cell):
                    cells = self._row_cells(0)
                    cells[cell] += " " + rogue
                    self.assertEqual(
                        self._errors(self._with_cells(0, cells)),
                        ["plan_repository_link_count_mismatch"],
                    )

    def test_repository_link_outside_second_cell(self):
        cells = self._row_cells(0)
        cells[0] = "[governance](https://github.com/rogue/repository)"
        cells[1] = "repository link missing"
        self.assertEqual(
            self._errors(self._with_cells(0, cells)),
            ["plan_repository_link_outside_repository_cell"],
        )

    def test_repository_cell_requires_fullmatch(self):
        for value in ("prefix ", " suffix"):
            with self.subTest(value=value):
                cells = self._row_cells(0)
                cells[1] = value + cells[1] if value.startswith("prefix") else cells[1] + value
                self.assertEqual(
                    self._errors(self._with_cells(0, cells)),
                    ["plan_full_name_mismatch"],
                )

    def test_repository_full_name_and_url_are_bound(self):
        plan = self._replace_cell_text(
            0,
            1,
            "`yurikuchumov-ux/ai-operating-system`",
            "`wrong/repository`",
        )
        self.assertEqual(self._errors(plan), ["plan_full_name_mismatch"])

        plan = self._replace_cell_text(
            0,
            1,
            "https://github.com/yurikuchumov-ux/ai-operating-system",
            "https://github.com/wrong/repository",
        )
        self.assertEqual(self._errors(plan), ["plan_url_mismatch"])

    def test_visibility_boundary_and_sha_are_bound(self):
        cells = self._row_cells(0)
        cells[2] = "private"
        self.assertEqual(
            self._errors(self._with_cells(0, cells)), ["plan_visibility_mismatch"]
        )

        cells = self._row_cells(0)
        cells[4] = "wrong boundary"
        self.assertEqual(
            self._errors(self._with_cells(0, cells)), ["plan_boundary_mismatch"]
        )

        for sha in ("`A" + "0" * 39 + "`", "`g" + "0" * 39 + "`", "`abc`", "0" * 40):
            with self.subTest(sha=sha):
                cells = self._row_cells(0)
                cells[3] = sha
                self.assertEqual(
                    self._errors(self._with_cells(0, cells)),
                    ["plan_main_sha_invalid"],
                )

        cells = self._row_cells(0)
        cells[3] = "`" + "0" * 40 + "`"
        self.assertEqual(self._errors(self._with_cells(0, cells)), [])

    def test_supplied_registry_fields_are_used(self):
        cases = (
            ("label", "changed label", "plan_label_set_mismatch"),
            ("full_name", "wrong/repository", "plan_full_name_mismatch"),
            ("url", "https://github.com/wrong/repository", "plan_url_mismatch"),
            ("visibility", "private", "plan_visibility_mismatch"),
            ("boundary", "wrong boundary", "plan_boundary_mismatch"),
        )
        for field, value, code in cases:
            with self.subTest(field=field):
                registry = copy.deepcopy(self.registry)
                registry["canonical_repositories"][0][field] = value
                self.assertEqual(self._errors(registry=registry), [code])


if __name__ == "__main__":
    unittest.main()
