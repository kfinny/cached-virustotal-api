from setuptools import setup, find_packages

with open('README.md', 'r') as fd:
      long_description = fd.read()

setup(name='kfinny.cachedvt',
      version='3.1.0',
      description='An extension of vt-py supporting local file cache',
      long_description=long_description,
      long_description_content_type="text/markdown",
      url='https://github.com/kfinny/cached-virustotal-api',
      author='Kevin Finnigin',
      author_email='kevin@finnigin.net',
      license='MIT',
      packages=find_packages(),
      install_requires=[
          'diskcache',
          'vt-py',
      ],
      zip_safe=False)
