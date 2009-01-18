import os
from setuptools import setup, find_packages

version = '2.0'

setup(name='plone.protect',
      version=version,
      description="Security for browser forms",
      long_description=open("README.txt").read() + "\n" + \
                       open(os.path.join("docs", "HISTORY.txt")).read(),
      classifiers=[
        "Framework :: Plone",
        "Framework :: Zope2",
        "Programming Language :: Python",
        ],
      keywords='zope security CSFS',
      author='Wichert Akkerman',
      author_email='plone-developers@lists.sourceforge.net',
      url='http://svn.plone.org/svn/plone/plone.protect',
      license='GPL',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['plone', ],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'setuptools',
          'plone.keyring > 1.0',
          'zope.component',
          'zope.deprecation',
          'zope.interface',
          # 'Zope2',
      ],
      )
