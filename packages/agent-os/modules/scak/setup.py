# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="scak",  # Short, memorable PyPI name
    version="2.1.0",  # Minor version bump for Agent OS monorepo
    description="Self-Correcting Agent Kernel: A specialized extension for Control Plane that implements Laziness Detection and Self-Correction loops using CMVK",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Self-Correcting Agent Team",
    author_email="research@scak.ai",
    url="https://github.com/microsoft/agent-governance-toolkit",
    project_urls={
        "Bug Tracker": "https://github.com/microsoft/agent-governance-toolkit/issues",
        "Documentation": "https://github.com/microsoft/agent-governance-toolkit/wiki",
        "Source Code": "https://github.com/microsoft/agent-governance-toolkit",
        "Changelog": "https://github.com/microsoft/agent-governance-toolkit/blob/main/CHANGELOG.md",
    },
    packages=find_packages(exclude=["tests*", "experiments*", "examples*", "notebooks*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Framework :: AsyncIO",
    ],
    # Layer 4: Core dependencies only - generic extension for any agent
    install_requires=[
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
        "agent-primitives>=0.1.0",  # Layer 1: Shared failure models
    ],
    extras_require={
        # Layer 3: Control Plane integration
        "control-plane": [
            "agent-control-plane>=1.0.0",
        ],
        # CMVK verification integration
        "cmvk": [
            "cmvk>=1.0.0",
        ],
        # Full Layer 4 stack (recommended for production)
        "full": [
            "agent-control-plane>=1.0.0",
            "cmvk>=1.0.0",
        ],
        # LLM clients for Shadow Teacher
        "llm": [
            "openai>=1.0.0",
            "anthropic>=0.7.0",
        ],
        # Development dependencies
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "streamlit>=1.28.0",
            "jupyter>=1.0.0",
        ],
        # All optional dependencies
        "all": [
            "agent-control-plane>=1.0.0",
            "cmvk>=1.0.0",
            "openai>=1.0.0",
            "anthropic>=0.7.0",
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "streamlit>=1.28.0",
            "jupyter>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "scak=cli:main",
        ],
        # Control Plane extension entry point
        "agent_control_plane.extensions": [
            "scak=src.integrations.control_plane_adapter:SCAKExtension",
        ],
    },
    python_requires=">=3.9",
    keywords="ai agents self-correction alignment llm production-ml scak control-plane cmvk laziness-detection",
    license="MIT",
)
