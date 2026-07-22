"""Regressions for the bounded raw-source Section 3.1 validator."""

import copy
import json
import unittest
from pathlib import Path

from tools.canonical_repository_plan import (
    SECTION_SENTINEL,
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
        self.sentinel = self.lines.index(SECTION_SENTINEL)
        self.header = self.sentinel + 2
        self.separator = self.sentinel + 3
        self.row_start = self.sentinel + 4

    def _document(self, lines):
        return "\n".join(lines) + ("\n" if self.plan.endswith("\n") else "")

    def _replace(self, index, value):
        lines = self.lines.copy()
        lines[index] = value
        return self._document(lines)

    def _insert(self, index, value):
        lines = self.lines.copy()
        lines.insert(index, value)
        return self._document(lines)

    def _delete(self, index):
        lines = self.lines.copy()
        del lines[index]
        return self._document(lines)

    def _cells(self, row=0):
        raw_cells = self._raw_cells(row)
        for raw_cell in raw_cells:
            self.assertGreaterEqual(len(raw_cell), 2)
            self.assertTrue(raw_cell.startswith(" "))
            self.assertTrue(raw_cell.endswith(" "))
        return [raw_cell[1:-1] for raw_cell in raw_cells]

    def _raw_cells(self, row=0):
        raw = self.lines[self.row_start + row]
        raw_cells = raw[1:-1].split("|")
        self.assertEqual(len(raw_cells), 5)
        return raw_cells

    def _with_cells(self, row, cells):
        return self._replace(
            self.row_start + row, "| " + " | ".join(cells) + " |"
        )

    def _with_raw_cells(self, row, raw_cells):
        return self._replace(
            self.row_start + row, "|" + "|".join(raw_cells) + "|"
        )

    def _errors(self, plan=_UNSET, registry=_UNSET):
        return validate_execution_plan(
            self.plan if plan is _UNSET else plan,
            self.registry if registry is _UNSET else registry,
        )

    def test_committed_inputs_pass(self):
        self.assertEqual(self._errors(), [])

    def test_input_types_fail(self):
        for plan in (None, 1, [], {}):
            with self.subTest(plan=plan):
                self.assertEqual(self._errors(plan=plan), ["plan_input_invalid"])
        for registry in (None, [], {}, {"canonical_repositories": {}}):
            with self.subTest(registry=registry):
                self.assertEqual(
                    self._errors(registry=registry), ["registry_input_invalid"]
                )

    def test_raw_sentinel_variants(self):
        self.assertEqual(
            self._errors(self._replace(self.sentinel, "### 3.2 Other")),
            ["plan_section_missing"],
        )
        self.assertEqual(
            self._errors(self._insert(self.sentinel + 1, SECTION_SENTINEL)),
            ["plan_section_duplicate"],
        )
        self.assertEqual(
            self._errors(
                self._replace(
                    self.sentinel, "## 3.1 Verified names and boundaries"
                )
            ),
            ["plan_section_wrong_level"],
        )
        self.assertEqual(
            self._errors(self._replace(self.sentinel, SECTION_SENTINEL + " changed")),
            ["plan_section_heading_suffix"],
        )

    def test_exact_blank_header_and_separator_sequence(self):
        self.assertEqual(
            self._errors(self._replace(self.sentinel + 1, " ")),
            ["plan_header_mismatch"],
        )
        for value in (
            " " + TABLE_HEADER,
            TABLE_HEADER + " ",
            TABLE_HEADER + " X",
            TABLE_HEADER[:-1] + "| Extra |",
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    self._errors(self._replace(self.header, value)),
                    ["plan_header_mismatch"],
                )
        for value in (
            " " + TABLE_SEPARATOR,
            TABLE_SEPARATOR + " ",
            TABLE_SEPARATOR[:-1] + " --- |",
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    self._errors(self._replace(self.separator, value)),
                    ["plan_separator_mismatch"],
                )

    def test_exact_three_contiguous_rows(self):
        self.assertEqual(
            self._errors(self._delete(self.row_start + 2)),
            ["plan_row_count_mismatch"],
        )
        self.assertEqual(
            self._errors(self._insert(self.row_start + 3, self.lines[self.row_start])),
            ["plan_row_count_mismatch"],
        )

    def test_raw_cells_are_preserved(self):
        cells = self._cells()
        for variant in (cells[:-1], cells + ["sixth"], cells + [""]):
            with self.subTest(variant=variant):
                self.assertEqual(
                    self._errors(self._with_cells(0, variant)),
                    ["plan_row_column_count_mismatch"],
                )
        row = self.lines[self.row_start]
        self.assertEqual(
            self._errors(self._replace(self.row_start, row + " ")),
            ["plan_row_column_count_mismatch"],
        )

    def test_every_raw_cell_rejects_extra_padding_and_tabs(self):
        for row in range(3):
            for cell in range(5):
                raw_cells = self._raw_cells(row)
                variants = {
                    "extra_leading_space": " " + raw_cells[cell],
                    "extra_trailing_space": raw_cells[cell] + " ",
                    "leading_tab": raw_cells[cell][0] + "\t" + raw_cells[cell][1:],
                    "trailing_tab": raw_cells[cell][:-1] + "\t" + raw_cells[cell][-1],
                }
                for variant, value in variants.items():
                    with self.subTest(row=row, cell=cell, variant=variant):
                        changed = raw_cells.copy()
                        changed[cell] = value
                        self.assertEqual(
                            self._errors(self._with_raw_cells(row, changed)),
                            ["plan_row_column_count_mismatch"],
                        )

    def test_literal_repository_url_token_count_and_location(self):
        rogue_base = "https://github.com/rogue/repository"
        suffixes = (
            "",
            "/",
            "/issues",
            "/tree/main",
            "?x=1",
            "#frag",
            "%2Fissues",
        )
        for row in range(3):
            for cell in (0, 2, 3, 4):
                for suffix in suffixes:
                    rogue = rogue_base + suffix
                    with self.subTest(
                        row=row, cell=cell, suffix=suffix, failure="count"
                    ):
                        cells = self._cells(row)
                        cells[cell] += " " + rogue
                        self.assertEqual(
                            self._errors(self._with_cells(row, cells)),
                            ["plan_repository_link_count_mismatch"],
                        )
                    with self.subTest(
                        row=row, cell=cell, suffix=suffix, failure="location"
                    ):
                        cells = self._cells(row)
                        cells[1] = "repository missing"
                        cells[cell] = rogue
                        self.assertEqual(
                            self._errors(self._with_cells(row, cells)),
                            ["plan_repository_link_outside_repository_cell"],
                        )

    def test_adjacent_repository_url_prefixes_are_counted(self):
        cells = self._cells()
        cells[1] = "repository missing"
        cells[4] = (
            "https://github.com/rogue/repository"
            "https://github.com/second/repository"
        )
        self.assertEqual(
            self._errors(self._with_cells(0, cells)),
            ["plan_repository_link_count_mismatch"],
        )

    def test_repository_cell_is_exact_and_registry_bound(self):
        cells = self._cells()
        for value in ("prefix " + cells[1], cells[1] + " suffix"):
            with self.subTest(value=value):
                changed = cells.copy()
                changed[1] = value
                self.assertEqual(
                    self._errors(self._with_cells(0, changed)),
                    ["plan_full_name_mismatch"],
                )

        changed = cells.copy()
        changed[1] = changed[1].replace(
            "`yurikuchumov-ux/ai-operating-system`", "`wrong/repository`"
        )
        self.assertEqual(
            self._errors(self._with_cells(0, changed)),
            ["plan_full_name_mismatch"],
        )

        changed = cells.copy()
        changed[1] = changed[1].replace(
            "https://github.com/yurikuchumov-ux/ai-operating-system",
            "https://github.com/wrong/repository",
        )
        self.assertEqual(
            self._errors(self._with_cells(0, changed)), ["plan_url_mismatch"]
        )

    def test_role_set_visibility_boundary_and_sha(self):
        cells = self._cells(1)
        cells[0] = self._cells(0)[0]
        self.assertEqual(
            self._errors(self._with_cells(1, cells)), ["plan_duplicate_label"]
        )

        cells = self._cells()
        cells[0] = "unknown role"
        self.assertEqual(
            self._errors(self._with_cells(0, cells)), ["plan_label_set_mismatch"]
        )

        for cell, value, code in (
            (2, "private", "plan_visibility_mismatch"),
            (4, "wrong boundary", "plan_boundary_mismatch"),
            (3, "`ABC`", "plan_main_sha_invalid"),
        ):
            with self.subTest(code=code):
                cells = self._cells()
                cells[cell] = value
                self.assertEqual(self._errors(self._with_cells(0, cells)), [code])

        cells = self._cells()
        cells[3] = "`" + "0" * 40 + "`"
        self.assertEqual(self._errors(self._with_cells(0, cells)), [])

    def test_every_registry_binding_is_authoritative(self):
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

    def test_every_registry_entry_field_is_structurally_required(self):
        fields = ("label", "full_name", "url", "visibility", "boundary")
        non_strings = (None, 1, True, [], {})
        for field in fields:
            with self.subTest(field=field, mutation="missing"):
                registry = copy.deepcopy(self.registry)
                del registry["canonical_repositories"][0][field]
                self.assertEqual(
                    self._errors(registry=registry), ["registry_input_invalid"]
                )
            for value in non_strings:
                with self.subTest(field=field, mutation="non_string", value=value):
                    registry = copy.deepcopy(self.registry)
                    registry["canonical_repositories"][0][field] = value
                    self.assertEqual(
                        self._errors(registry=registry), ["registry_input_invalid"]
                    )

    def test_registry_labels_and_entries_fail_closed_before_plan_semantics(self):
        registry = copy.deepcopy(self.registry)
        registry["canonical_repositories"][0]["label"] = ""
        self.assertEqual(self._errors(registry=registry), ["registry_input_invalid"])

        registry = copy.deepcopy(self.registry)
        registry["canonical_repositories"][1]["label"] = registry[
            "canonical_repositories"
        ][0]["label"]
        self.assertEqual(self._errors(registry=registry), ["registry_input_invalid"])

        for value in (None, 1, True, [], "not an object"):
            with self.subTest(entry=value):
                registry = copy.deepcopy(self.registry)
                registry["canonical_repositories"][0] = value
                self.assertEqual(
                    self._errors(plan="not the governed section", registry=registry),
                    ["registry_input_invalid"],
                )

    def test_multiple_semantic_failures_are_sorted(self):
        lines = self.lines.copy()

        cells = self._cells(0)
        cells[2] = "private"
        lines[self.row_start] = "| " + " | ".join(cells) + " |"

        cells = self._cells(1)
        cells[4] = "wrong boundary"
        lines[self.row_start + 1] = "| " + " | ".join(cells) + " |"

        cells = self._cells(2)
        cells[3] = "`ABC`"
        lines[self.row_start + 2] = "| " + " | ".join(cells) + " |"

        self.assertEqual(
            self._errors(self._document(lines)),
            [
                "plan_boundary_mismatch",
                "plan_main_sha_invalid",
                "plan_visibility_mismatch",
            ],
        )

    def test_repeated_semantic_error_is_unique(self):
        lines = self.lines.copy()
        for row in (0, 1):
            cells = self._cells(row)
            cells[4] = "wrong boundary"
            lines[self.row_start + row] = "| " + " | ".join(cells) + " |"

        self.assertEqual(
            self._errors(self._document(lines)),
            ["plan_boundary_mismatch"],
        )


if __name__ == "__main__":
    unittest.main()
