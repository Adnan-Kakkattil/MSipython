from setuptools import setup, Extension
from Cython.Build import cythonize

# Define the paths to your Cython files
extensions = [
    Extension("installation", ["installation.pyx"]),
    Extension("uninstallation", ["uninstallation.pyx"]),  # ✅ Added uninstallation file
    Extension("autostart", ["autostart.pyx"]),
    Extension("utils.service", ["utils/service.pyx"]),
]

setup(
    name="InstallationSetup",
    ext_modules=cythonize(
        extensions,
        compiler_directives={"language_level": "3"},  # Use Python 3 syntax
    ),
)
