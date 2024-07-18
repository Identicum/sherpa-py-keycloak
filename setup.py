# sherpa-py-janssen is available under the MIT License. https://github.com/Identicum/sherpa-py-janssen/
# Copyright (c) 2024, Identicum - https://identicum.com/
#
# Author: Gustavo J Gallardo - ggallard@identicum.com
#

from setuptools import setup

setup(
    name='sherpa-py-keycloak',
    version='1.0.20240718',
    description='Python utilities for Keycloak',
    url='git@github.com:Identicum/sherpa-py-keycloak.git',
    author='Identicum',
    author_email='ggallard@identicum.com',
    license='MIT License',
    install_requires=['sherpa-py-utils', 'python-keycloak==4.2.2'],
    packages=['sherpa.keycloak'],
    zip_safe=False,
    python_requires='>=3.0'
)