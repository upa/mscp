from setuptools import setup, Extension, find_packages

setup(
    name='mscp',
    version = "0.0.1",
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
