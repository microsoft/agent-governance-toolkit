# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Each subpackage is a self-contained governance scenario.

A scenario package holds its test and runner in ``test_<name>.py``, with a
neighboring policy artifact where applicable (``acs.manifest.yaml`` for the
ACS policy scenarios, ``policy.yaml`` for other config-driven scenarios).
"""
