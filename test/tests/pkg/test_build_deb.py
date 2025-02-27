import pytest

pytestmark = pytest.mark.deb


# This test has the side effect of building the package and leaving it in the
# project's parent directory.
def test_deb_build(deb_package, skip_unless_deb):
    """Test that the package can be built."""
    assert deb_package.exists(), f"Package {deb_package} not found"
