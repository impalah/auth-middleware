import pytest
from ksuid import Ksuid

PERSON_ID: str = str(Ksuid())


@pytest.mark.asyncio
async def test_create_success():
    variable: bool = True
    assert variable
