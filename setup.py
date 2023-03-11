from distutils.core import setup, Extension

setup(
    name='pymscp',
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
