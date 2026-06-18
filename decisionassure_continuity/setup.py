from setuptools import setup, find_packages

setup(
    name="decisionassure-continuity",
    version="1.0.0",
    description="Constitutional continuity verification for AI agents",
    author="Akhilesh Warik",
    author_email="warikakhilesh319@gmail.com",
    packages=find_packages(),
    install_requires=[
        "pydantic>=2.0.0",
        "numpy>=1.26.0",
        "click>=8.0.0",
    ],
    entry_points={
        "console_scripts": [
            "continuity=src.continuity_cli:cli",
        ],
    },
    python_requires=">=3.10",
    license="MIT",
)