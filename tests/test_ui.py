from jwtek.core import ui


def test_path_completion_lists_directory_contents(tmp_path):
    (tmp_path / "alpha").mkdir()
    (tmp_path / "bravo.txt").write_text("data")

    matches = ui._path_completion_options("", base_dir=str(tmp_path))

    assert "alpha/" in matches
    assert "bravo.txt" in matches


def test_path_completion_with_prefix_and_nested_dirs(tmp_path):
    nested = tmp_path / "alpha" / "nested"
    nested.mkdir(parents=True)
    (tmp_path / "alphabet.txt").write_text("data")

    matches = ui._path_completion_options("al", base_dir=str(tmp_path))
    assert matches == ["alpha/", "alphabet.txt"]

    nested_matches = ui._path_completion_options("alpha/", base_dir=str(tmp_path))
    assert nested_matches == ["alpha/nested/"]

    deeper_matches = ui._path_completion_options("alpha/n", base_dir=str(tmp_path))
    assert deeper_matches == ["alpha/nested/"]
