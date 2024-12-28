from datetime import datetime
from typing import Optional, cast

from sqlalchemy import Column, DateTime, String
from sqlalchemy.orm import Mapped, declarative_base, mapped_column

Base = declarative_base()
metadata = Base.metadata


class BaseModel:
    """Common model"""

    __tablename__ = "common_base"
    # change your schema here
    # __table_args__ = ({'schema': 'core_schema'})

    # created_by: Mapped[str] = mapped_column(String(500), nullable=True)
    # created_at: Mapped[datetime] = mapped_column(
    #     DateTime(timezone=False), default=datetime.now()
    # )
    # updated_by: Mapped[str] = mapped_column(String(500), nullable=True)
    # updated_at: Mapped[datetime] = mapped_column(
    #     DateTime(timezone=False),
    #     default=datetime.now(),
    #     onupdate=datetime.now(),
    # )
