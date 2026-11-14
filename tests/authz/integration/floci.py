"""Floci (https://github.com/floci-io/floci) through testcontainers.

One container emulates DynamoDB natively and RDS by starting *real* PostgreSQL and
MySQL containers, so the three stores run against the three engines. RDS needs the
Docker socket. Everything is skipped when Docker or ``testcontainers`` is missing.

Override the image with ``AUTHZ_TEST_FLOCI_IMAGE`` (default: a pinned version).
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest

FLOCI_IMAGE = os.environ.get("AUTHZ_TEST_FLOCI_IMAGE", "floci/floci:2.3.0")
RDS_PORTS = range(7001, 7011)
PASSWORD = "Passw0rd-authz"
DB_NAME = "authz"


@dataclass(frozen=True)
class FlociStack:
    endpoint: str
    _container: Any

    def client(self, service: str) -> Any:
        import boto3

        return boto3.client(
            service,
            endpoint_url=self.endpoint,
            region_name="us-east-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )

    def database_url(self, engine: str, driver: str) -> str:
        """Create an RDS instance (a real DB container) and return a SQLAlchemy URL."""
        rds = self.client("rds")
        name = f"authz-{engine}"
        rds.create_db_instance(
            DBInstanceIdentifier=name,
            Engine=engine,
            DBInstanceClass="db.t3.micro",
            MasterUsername="admin",
            MasterUserPassword=PASSWORD,
            AllocatedStorage=5,
            DBName=DB_NAME,
        )
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            info = rds.describe_db_instances(DBInstanceIdentifier=name)["DBInstances"][
                0
            ]
            if info["DBInstanceStatus"] == "available":
                port = self._container.get_exposed_port(info["Endpoint"]["Port"])
                host = self._container.get_container_host_ip()
                url = f"{driver}://admin:{PASSWORD}@{host}:{port}/{DB_NAME}"
                self._wait_until_accepting(url, deadline)
                return url
            time.sleep(1)
        raise TimeoutError(f"RDS {engine} did not become available")

    @staticmethod
    def _wait_until_accepting(url: str, deadline: float) -> None:
        """RDS says 'available' while the engine is still initialising: really connect."""
        import asyncio

        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import create_async_engine

        async def probe() -> None:
            engine = create_async_engine(url)
            try:
                async with engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
            finally:
                await engine.dispose()

        while True:
            try:
                asyncio.run(probe())
                return
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(2)

    def drop_database(self, engine: str) -> None:
        try:
            self.client("rds").delete_db_instance(
                DBInstanceIdentifier=f"authz-{engine}", SkipFinalSnapshot=True
            )
        except Exception:  # best effort: the container is removed at exit anyway
            pass


def _docker_available() -> bool:
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def floci() -> Iterator[FlociStack]:
    pytest.importorskip("testcontainers")
    if not _docker_available():
        pytest.skip("Docker is not available")
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.waiting_utils import wait_for_logs

    container = (
        DockerContainer(FLOCI_IMAGE)
        .with_exposed_ports(4566, *RDS_PORTS)
        .with_volume_mapping("/var/run/docker.sock", "/var/run/docker.sock", "rw")
    )
    with container:
        wait_for_logs(container, "Listening on", timeout=60)
        host = container.get_container_host_ip()
        port = container.get_exposed_port(4566)
        yield FlociStack(f"http://{host}:{port}", container)
