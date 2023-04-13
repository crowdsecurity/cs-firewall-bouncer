
def test_buildpackage(deb_package_file):
    """Test that the package can be built."""
    assert deb_package_file.exists(), f'Package {deb_package_file} not found'
