from setuptools import setup, find_packages

setup(name='kfinny.cachedvt',
      version='2.0.0',
      description='An extension of virustotal-api supporting local file cache',
      url='https://github.com/kfinny/cached-virustotal-api',
      author='Kevin Finnigin',
      author_email='kevin@finnigin.net',
      license='MIT',
      packages=find_packages(),
      install_requires=[
          'diskcache',
          'virustotal-api',
      ],
      zip_safe=False)
