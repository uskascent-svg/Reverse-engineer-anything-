import unittest

from evaluate import score, load_labels


class EvaluationTests(unittest.TestCase):
    def test_confusion_matrix_and_metrics(self):
        result = score({"a": True, "b": True, "c": False, "d": False}, {"a", "c"})
        self.assertEqual(result["confusion_matrix"], {
            "true_positive": 1, "false_positive": 1,
            "false_negative": 1, "true_negative": 1
        })
        self.assertEqual(result["metrics"]["precision"], 0.5)
        self.assertEqual(result["metrics"]["recall"], 0.5)
        self.assertEqual(result["metrics"]["accuracy"], 0.5)

    def test_no_positive_predictions_are_zero_not_division_error(self):
        result = score({"a": True, "b": False}, set())
        self.assertEqual(result["metrics"]["precision"], 0.0)
        self.assertEqual(result["metrics"]["recall"], 0.0)

    def test_unlabeled_predictions_are_reported(self):
        result = score({"a": True, "b": False}, {"a", "not-labeled"})
        self.assertEqual(result["predictions_without_labels_excluded"], 1)
        self.assertEqual(result["confusion_matrix"]["true_positive"], 1)


if __name__ == "__main__":
    unittest.main()
