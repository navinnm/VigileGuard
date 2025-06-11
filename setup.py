#!/usr/bin/env python3
"""
VigileGuard Setup Script
========================

Installation script for VigileGuard Linux Security Audit Tool
"""

from setuptools import setup, find_packages
import os
import sys

# Read version from package
def get_version():
    version_file = os.path.join(os.path.dirname(__file__), 'vigileguard', '__init__.py')
    if os.path.exists(version_file):
        with open(version_file, 'r') as f:
            for line in f:
                if line.startswith('__version__'):
                    return line.split('=')[1].strip().strip('"').strip("'")
    return "2.0.0"

# Read long description from README
def get_long_description():
    readme_file = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_file):
        with open(readme_file, 'r', encoding='utf-8') as f:
            return f.read()
    return "VigileGuard - Comprehensive Linux Security Audit Tool"

# Base requirements for Phase 1
base_requirements = [
    'click>=8.0.0',
    'PyYAML>=5.4.0',
    'rich>=10.0.0',
]

# Additional requirements for Phase 2
phase2_requirements = [
    'requests>=2.25.0',
    'jinja2>=3.0.0',
]

# Development requirements
dev_requirements = [
    'pytest>=6.0.0',
    'pytest-cov>=2.10.0',
    'black>=21.0.0',
    'flake8>=3.8.0',
    'mypy>=0.800',
    'bandit>=1.7.0',
    'safety>=1.10.0',
]

setup(
    name="vigileguard",
    version=get_version(),
    author="VigileGuard Development Team",
    author_email="security@vigileguard.org",
    description="Comprehensive Linux Security Audit Tool",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/navinnm/VigileGuard",
    project_urls={
        "Bug Reports": "https://github.com/navinnm/VigileGuard/issues",
        "Source": "https://github.com/navinnm/VigileGuard",
        "Documentation": "https://github.com/navinnm/VigileGuard/wiki",
    },
    packages=find_packages(),
    package_data={
        'vigileguard': [
            '*.py',
            '*.yaml',
            '*.yml',
            'config/*.yaml',
            'templates/*.html',
            'templates/*.j2',
        ],
    },
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=base_requirements,
    extras_require={
        "dev": dev_requirements,
        "full": base_requirements + phase2_requirements,
        "phase2": phase2_requirements,
        "all": base_requirements + phase2_requirements + dev_requirements,
    },
    entry_points={
        "console_scripts": [
            "vigileguard=vigileguard:main",
            "vigileguard-cli=vigileguard.vigileguard:main",
        ],
    },
    scripts=[
        'scripts/vigileguard-setup-cron.sh',
    ] if os.path.exists('scripts/vigileguard-setup-cron.sh') else [],
    zip_safe=False,
    keywords=[
        "security", "audit", "linux", "system", "administration", 
        "vulnerability", "scanner", "compliance", "hardening"
    ],
    platforms=["linux"],
    license="MIT",
    
    # Ensure all Python files are included
    data_files=[
        ('vigileguard', [
            'vigileguard/vigileguard.py',
            'vigileguard/web_security_checkers.py',
            'vigileguard/enhanced_reporting.py', 
            'vigileguard/phase2_integration.py',
            'vigileguard/__init__.py',
        ]),
    ] if all(os.path.exists(f'vigileguard/{f}') for f in [
        'vigileguard.py', 'web_security_checkers.py', 
        'enhanced_reporting.py', 'phase2_integration.py', '__init__.py'
    ]) else [],
    
    # Custom commands for post-install setup
    cmdclass={},
)

# Post-installation message
if __name__ == "__main__":
    # Check if this is an installation
    if len(sys.argv) > 1 and 'install' in sys.argv:
        print("\n" + "="*60)
        print("🛡️  VigileGuard Installation Complete!")
        print("="*60)
        print("\nTo get started:")
        print("  1. Run: vigileguard --help")
        print("  2. Basic scan: vigileguard")
        print("  3. JSON output: vigileguard --format json")
        print("  4. HTML report: vigileguard --format html")
        print("  5. All formats: vigileguard --format all")
        print("\nFor configuration:")
        print("  vigileguard --create-sample-config config.yaml")
        print("  vigileguard --config config.yaml")
        print("\nRepository: https://github.com/navinnm/VigileGuard")
        print("Documentation: https://github.com/navinnm/VigileGuard/wiki")
        print("="*60)
    
    # Run the normal setup
    setup()