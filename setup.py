#!/usr/bin/env python3
"""
VigileGuard Setup Script
Packages VigileGuard with both Phase 1 and Phase 2 components
"""

from setuptools import setup, find_packages
import os
from pathlib import Path

# Read version from __init__.py
def get_version():
    init_file = Path(__file__).parent / "vigileguard" / "__init__.py"
    if init_file.exists():
        with open(init_file, 'r') as f:
            for line in f:
                if line.startswith('__version__'):
                    return line.split('=')[1].strip().strip('"\'')
    return "2.0.0"

# Read long description from README
def get_long_description():
    readme_file = Path(__file__).parent / "README.md"
    if readme_file.exists():
        with open(readme_file, 'r', encoding='utf-8') as f:
            return f.read()
    return "VigileGuard - Linux Security Audit Tool"

# Read requirements
def get_requirements():
    req_file = Path(__file__).parent / "requirements.txt"
    if req_file.exists():
        with open(req_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return ['click>=8.1.7', 'rich>=13.7.0', 'PyYAML>=6.0.1', 'requests>=2.25.0']

setup(
    name="vigileguard",
    version=get_version(),
    author="VigileGuard Development Team",
    author_email="security@vigileguard.dev",
    description="Comprehensive Linux Security Audit Tool with Phase 1 & 2 Features",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/navinnm/VigileGuard",
    project_urls={
        "Bug Tracker": "https://github.com/navinnm/VigileGuard/issues",
        "Documentation": "https://github.com/navinnm/VigileGuard/blob/main/docs/",
        "Source Code": "https://github.com/navinnm/VigileGuard",
    },
    
    # Package configuration
    packages=find_packages(),
    package_data={
        'vigileguard': [
            '*.yaml',
            '*.yml', 
            '*.json',
            'templates/*.html',
            'static/*.css',
            'static/*.js'
        ],
    },
    include_package_data=True,
    
    # Dependencies
    install_requires=get_requirements(),
    extras_require={
        'dev': [
            'pytest>=6.0',
            'pytest-cov>=2.0',
            'black>=21.0',
            'flake8>=3.8',
            'mypy>=0.800',
            'bandit>=1.7',
            'safety>=1.10'
        ],
        'notifications': [
            'requests>=2.25.0',
            'smtplib-ssl>=1.0'  # For secure email notifications
        ],
        'full': [
            'requests>=2.25.0',
            'smtplib-ssl>=1.0',
            'pytest>=6.0',
            'pytest-cov>=2.0'
        ]
    },
    
    # Entry points for command line usage
    entry_points={
        'console_scripts': [
            'vigileguard=vigileguard.vigileguard:main',
            'vigileguard-phase2=vigileguard.phase2_integration:main_phase2',
            'vigileguard-report=vigileguard.enhanced_reporting:generate_report_cli',
            'vigileguard-config=vigileguard.phase2_integration:config_cli',
        ],
    },
    
    # Metadata
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
    ],
    
    # Python version requirement
    python_requires=">=3.8",
    
    # Keywords for PyPI
    keywords=[
        "security", "audit", "linux", "compliance", "vulnerability",
        "scanning", "assessment", "hardening", "monitoring", "reporting"
    ],
    
    # License
    license="MIT",
    
    # Zip safe
    zip_safe=False,
    
    # Scripts
    scripts=[
        'scripts/vigileguard-install.sh',
        'scripts/vigileguard-setup-cron.sh'
    ] if os.path.exists('scripts/') else [],
)

# Post-installation message
print("""
🛡️ VigileGuard Installation Complete!

Phase 1 + Phase 2 Features Available:
✅ File permission analysis
✅ User account security checks  
✅ SSH configuration review
✅ System information gathering
✅ Web server security auditing
✅ Network security analysis
✅ Enhanced HTML reporting
✅ Compliance mapping
✅ Notification integrations

Quick Start:
  vigileguard --help
  vigileguard --format console
  vigileguard --format html --output report.html
  vigileguard --format json --output report.json

Documentation: https://github.com/navinnm/VigileGuard
""")