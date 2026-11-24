# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for result limits on VectorStoreIntegration.
"""

import unittest

from agent_control_plane.multimodal import VectorDocument, VectorStoreIntegration


def _store(count):
    store = VectorStoreIntegration.__new__(VectorStoreIntegration)
    store._documents = {
        f"d{i}": VectorDocument(
            doc_id=f"d{i}", content=f"content-{i}", embedding=[float(i)]
        )
        for i in range(count)
    }
    return store


class TestListDocumentsLimit(unittest.TestCase):
    """list_documents: None returns everything, 0 returns none."""

    def test_none_returns_every_document(self):
        self.assertEqual(len(_store(5).list_documents()), 5)
        self.assertEqual(len(_store(5).list_documents(limit=None)), 5)

    def test_zero_returns_no_documents(self):
        self.assertEqual(_store(5).list_documents(limit=0), [])

    def test_positive_limit_truncates(self):
        self.assertEqual(len(_store(5).list_documents(limit=2)), 2)

    def test_limit_above_the_document_count_returns_every_document(self):
        self.assertEqual(len(_store(3).list_documents(limit=99)), 3)

    def test_negative_limit_is_rejected(self):
        for limit in (-1, -5):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    _store(5).list_documents(limit=limit)


class TestSearchTopK(unittest.TestCase):
    """search: 0 already returned none; negatives are now rejected."""

    def test_zero_returns_no_results(self):
        self.assertEqual(_store(5).search([1.0], top_k=0), [])

    def test_positive_top_k_truncates(self):
        self.assertEqual(len(_store(5).search([1.0], top_k=2)), 2)

    def test_top_k_above_the_document_count_returns_every_result(self):
        self.assertEqual(len(_store(3).search([1.0], top_k=99)), 3)

    def test_negative_top_k_is_rejected(self):
        for top_k in (-1, -5):
            with self.subTest(top_k=top_k):
                with self.assertRaises(ValueError):
                    _store(5).search([1.0], top_k=top_k)

    def test_empty_store_returns_no_results(self):
        self.assertEqual(_store(0).search([1.0], top_k=5), [])


if __name__ == "__main__":
    unittest.main()
