#!/usr/bin/env python
from setuptools import setup, find_packages

version = '0.0.1'
author = 'David-Leon Pohl'
author_email = 'David-Leon.Pohl@rub.de'

setup(
    name='ilightsln',
    version=version,
    description='Connect to a ILightSln zigbee gateway via network to control the lights',
    url='https://github.com/DavidLP/ilightsln',
    license='MIT License',
    long_description='',
    author=author,
    maintainer=author,
    author_email=author_email,
    maintainer_email=author_email,
    packages=find_packages(),
    include_package_data=True,  # Accept all data files and directories matched by MANIFEST.in or found in source control
    keywords=['zigbee', 'light'],
    platforms='any'
)
