#!/usr/bin/env python3
"""
SecurePulse Setup Script
"""

from setuptools import setup, find_packages
import os

# Read README file
def read_readme():
    with open('README.md', 'r', encoding='utf-8') as f:
        return f.read()

# Read requirements
def read_requirements():
    with open('requirements.txt', 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='securepulse',
    version='1.0.0',
    description='Linux Security Audit Tool for System Hardening and Compliance',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    author='SecurePulse Development Team',
    author_email='security@yourcompany.com',
    url='https://github.com/yourcompany/securepulse',
    license='MIT',
    
    packages=find_packages(),
    
    install_requires=read_requirements(),
    
    entry_points={
        'console_scripts': [
            'securepulse=securepulse.main:main',
            'sp=securepulse.main:main',  # Short alias
        ],
    },
    
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        'Topic :: System :: Monitoring',
    ],
    
    keywords='security audit linux hardening compliance devops',
    
    python_requires='>=3.8',
    
    package_data={
        'securepulse': [
            'config/*.yaml',
            'templates/*.json',
        ],
    },
    
    include_package_data=True,
    
    zip_safe=False,
    
    project_urls={
        'Bug Reports': 'https://github.com/yourcompany/securepulse/issues',
        'Source': 'https://github.com/yourcompany/securepulse',
        'Documentation': 'https://securepulse.readthedocs.io/',
    },
)