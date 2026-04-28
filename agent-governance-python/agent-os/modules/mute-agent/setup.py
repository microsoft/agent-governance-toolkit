# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Setup configuration for the Mute Agent package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mute-agent",
    version="3.1.0",
    author="Mute Agent Team",
    description="Layer 5 Reference Implementation - Listener Agent with Dynamic Semantic Handshake Protocol",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/microsoft/agent-governance-toolkit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Layer dependencies (consolidated stack)
        # These are the allowed dependencies per Layer 5 specification:
        # - agent-control-plane>=0.1.0  # Base orchestration (when available)
        # - scak>=0.1.0                 # Intelligence layer (when available)
        # - iatp>=0.1.0                 # Security layer (when available)
        # - caas>=0.1.0                 # Context layer (when available)
        #
        # Currently using mock adapters until dependencies are published
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0,<9.0.0",
            "pytest-cov>=4.0.0,<6.0.0",
            "black>=22.0.0,<25.0.0",
            "flake8>=5.0.0,<8.0.0",
            "mypy>=0.990,<2.0.0",
        ],
        "viz": [
            # For visualization and benchmarking
            "matplotlib>=3.5.0",
            # For graph visualization (Phase 3: Evidence Layer)
            "networkx>=2.6.0",
            "pyvis>=0.3.0",
        ],
        # Full stack with all layer dependencies (when available)
        "full": [
            # "agent-control-plane>=0.1.0",
            # "scak>=0.1.0",
            # "iatp>=0.1.0",
            # "caas>=0.1.0",
        ],
    },
)
