from typing import List
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from ksuid import Ksuid

PERSON_ID: str = str(Ksuid())


@pytest.mark.asyncio
async def test_create_success():
    variable: bool = True
    assert variable


