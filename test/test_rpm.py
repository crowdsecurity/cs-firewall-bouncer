
import pytest

pytestmark = pytest.mark.rpm


def test_rpm_build(rpm_package_path):
    """Test that the package can be built."""
    assert rpm_package_path.exists(), f'Package {rpm_package_path} not found'
