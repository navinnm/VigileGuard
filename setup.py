"""
VigileGuard Security Audit Engine - Setup Script
Phase 3: API & CI/CD Integration
"""

from setuptools import setup, find_packages
import os

# Read README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vigileguard",
    version="3.0.3",
    author="VigileGuard Team",
    author_email="team@vigileguard.com",
    description="Comprehensive Security Audit Engine with API & CI/CD Integration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/navinnm/VigileGuard",
    project_urls={
        "Bug Tracker": "https://github.com/navinnm/VigileGuard/issues",
        "Documentation": "https://docs.vigileguard.com",
        "Homepage": "https://vigileguard.com",
        "API Docs": "http://localhost:8000/api/docs",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Unix",
    ],
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.910",
        ],
        "api": [
            "fastapi>=0.104.0",
            "uvicorn>=0.24.0",
            "pydantic>=2.0.0",
            "python-multipart>=0.0.6",
            "aiofiles>=23.0.3",
            "httpx>=0.25.0",
        ],
        "ci": [
            "requests>=2.28.0",
            "pyyaml>=6.0.1",
        ]
    },
    entry_points={
        "console_scripts": [
            "vigileguard=vigileguard.vigileguard:main",
            "vigileguard-api=api.main:main",
        ],
    },
    package_data={
        "vigileguard": ["*.yaml", "*.yml"],
        "api": ["*.yaml", "*.yml"],
        "integrations": ["**/*"],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="security audit vulnerability scanner ci-cd api",
    platforms=["Linux", "Unix"],
)