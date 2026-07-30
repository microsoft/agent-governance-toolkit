# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Route modules for the Engine API reference adapter.

One module per route group. Each module exposes an ``APIRouter`` named ``router`` whose
operations are decorated with
:func:`~agentmesh.engine_api.capabilities.capability_flags`. The app factory in
:mod:`agentmesh.engine_api.app` includes each router and applies the capability-extension
OpenAPI hook after all routers are registered.
"""
