# Step 1: Create setup.py
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vigileguard",
    version="1.0.0",
    author="VigileGuard Development Team",
    author_email="ping@fulgid.in",  # Update this
    description="A comprehensive Linux security audit tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/navinnm/VigileGuard",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "vigileguard=vigileguard:main",
        ],
    },
    keywords="security audit linux cybersecurity pentesting vulnerability scanner",
    project_urls={
        "Bug Reports": "https://github.com/navinnm/VigileGuard/issues",
        "Source": "https://github.com/navinnm/VigileGuard",
        "Documentation": "https://github.com/navinnm/VigileGuard#readme",
    },
)