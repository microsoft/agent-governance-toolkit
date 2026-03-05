#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Generate Python gRPC stubs from IATP Protocol Buffers.

This script generates Python code from the iatp.proto file,
creating both message classes and gRPC service stubs.

Usage:
    python generate_stubs.py

Requirements:
    pip install grpcio-tools

Output:
    iatp/generated/
        iatp_pb2.py       - Message classes
        iatp_pb2.pyi      - Type stubs for IDE support
        iatp_pb2_grpc.py  - gRPC service stubs
"""

import subprocess
import sys
from pathlib import Path


def main():
    """Generate Python gRPC stubs."""
    # Paths
    proto_dir = Path(__file__).parent
    iatp_dir = proto_dir.parent / "iatp"
    generated_dir = iatp_dir / "generated"
    proto_file = proto_dir / "iatp.proto"
    
    # Create output directory
    generated_dir.mkdir(parents=True, exist_ok=True)
    
    # Create __init__.py
    init_file = generated_dir / "__init__.py"
    init_file.write_text('"""Generated gRPC stubs for IATP."""\n')
    
    # Check if grpcio-tools is installed
    try:
        import grpc_tools.protoc
    except ImportError:
        print("Error: grpcio-tools not installed.")
        print("Install with: pip install grpcio-tools")
        sys.exit(1)
    
    # Generate stubs
    print(f"Generating Python stubs from {proto_file}")
    print(f"Output directory: {generated_dir}")
    
    # Build command
    cmd = [
        sys.executable, "-m", "grpc_tools.protoc",
        f"-I{proto_dir}",
        f"--python_out={generated_dir}",
        f"--pyi_out={generated_dir}",
        f"--grpc_python_out={generated_dir}",
        str(proto_file),
    ]
    
    print(f"Running: {' '.join(cmd)}")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Error generating stubs:")
        print(result.stderr)
        sys.exit(1)
    
    print("Successfully generated:")
    for f in generated_dir.glob("*.py"):
        print(f"  - {f.name}")
    
    print("\nUsage:")
    print("  from iatp.generated import iatp_pb2, iatp_pb2_grpc")


if __name__ == "__main__":
    main()
