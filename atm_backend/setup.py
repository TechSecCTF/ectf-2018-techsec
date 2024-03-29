from setuptools import setup, find_packages

from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='atm_backend',
    version='1.0.0',
    description='A sample Python project',
    long_description=long_description,
    url='',
    python_requires='<3',
    packages=find_packages(include=['atm_backend', 'interface'], exclude=['contrib', 'docs', 'tests']),

    install_requires=['pyserial', 'pycrypto'],

    # $ pip install -e .[dev,test]
    extras_require={
        'dev': ['check-manifest'],
        'test': ['nose'],
    },
    test_suite='nose.collector',

    tests_require=['nose'],

    # package_data={
    #     'pyUploader': ['package_data.dat'],
    # },

    entry_points={
        'console_scripts': [
            'atm_backend=atm_backend:main',
        ],
    },
)
