#!/usr/bin/env python
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Setup script for Agent Control Plane

Note: This file is maintained for backward compatibility.
Modern installations should use pyproject.toml directly.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="agent-control-plane",
    version="1.2.0",
    author="Imran Siddique",
    author_email="agt@microsoft.com",
    description="A deterministic kernel for zero-violation governance in agentic AI systems",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/microsoft/agent-governance-toolkit",
    project_urls={
        "Bug Tracker": "https://github.com/microsoft/agent-governance-toolkit/issues",
        "Documentation": "https://github.com/microsoft/agent-governance-toolkit/tree/main/docs",
        "Source Code": "https://github.com/microsoft/agent-governance-toolkit",
        "Paper": "https://arxiv.org/abs/XXXX.XXXXX",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Typing :: Typed",
    ],
    python_requires=">=3.8",
    install_requires=[
        # No external dependencies - uses only Python standard library
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "hf": [
            "huggingface_hub>=0.20.0",
            "datasets>=2.14.0",
        ],
    },
    keywords="ai agents governance control-plane safety policy agentic-ai llm guardrails deterministic",
    zip_safe=False,
)
