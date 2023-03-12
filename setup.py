from setuptools import setup, Extension, find_packages
import os

mypackage_root_dir = os.path.dirname(__file__)
with open(os.path.join(mypackage_root_dir, 'VERSION')) as version_file:
    version = version_file.read().strip()

setup(
    name='mscp',
    version = version,
    description = "libmscp python binding",
    author = "Ryo Nakamura",
    author_email = "upa@haeena.net",
    url = "https://github.com/upa/mscp",
    packages = find_packages("mscp"),
    package_dir = {"": "mscp"},
    py_modules = [ "mscp" ],
    ext_modules = [
        Extension(
            'pymscp',
            ['src/pymscp.c'],
            library_dirs = ['build'],
            libraries = ['mscp'],
            include_dirs = ['include']
        )
    ]
)
