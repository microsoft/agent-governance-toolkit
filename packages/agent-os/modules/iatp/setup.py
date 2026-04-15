# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="inter-agent-trust-protocol",
    version="3.1.0",
    author="Microsoft Corporation",
    author_email="agentgovtoolkit@microsoft.com",
    description="Inter-Agent Trust Protocol - Envoy for Agents with Typed IPC Pipes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/microsoft/agent-governance-toolkit",
    project_urls={
        "Bug Tracker": "https://github.com/microsoft/agent-governance-toolkit/issues",
        "Documentation": "https://github.com/microsoft/agent-governance-toolkit",
        "Source Code": "https://github.com/microsoft/agent-governance-toolkit",
    },
    packages=find_packages(exclude=["tests", "tests.*", "examples", "examples.*", "experiments", "experiments.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Distributed Computing",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "fastapi>=0.109.1",
        "uvicorn>=0.27.0",
        "pydantic>=2.5.3",
        "httpx>=0.26.0",
        "python-dateutil>=2.8.2",
        "agent-primitives>=0.1.0",
        "click>=8.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
        ],
    },
    python_requires=">=3.8",
    keywords="agent ai llm trust security sidecar mesh governance policy",
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "iatp=iatp.cli:cli",
        ],
    },
)
