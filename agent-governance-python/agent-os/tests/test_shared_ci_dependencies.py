# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


def test_anyio_streams_import_with_shared_ci_dependencies() -> None:
    from anyio.abc import ObjectReceiveStream

    assert ObjectReceiveStream is not None
