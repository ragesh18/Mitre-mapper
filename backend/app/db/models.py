import datetime as dt

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from .database import Base


class Technique(Base):
    __tablename__ = "techniques"
    id = Column(Integer, primary_key=True)
    attack_id = Column(String(16), unique=True, index=True, nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    tactics = Column(String(300), default="")  # comma-separated
    platforms = Column(String(300), default="")
    url = Column(String(300), default="")
    is_subtechnique = Column(Boolean, default=False)

    def to_dict(self, full=False):
        d = {
            "attack_id": self.attack_id, "name": self.name,
            "tactics": [t for t in (self.tactics or "").split(",") if t],
            "platforms": [p for p in (self.platforms or "").split(",") if p],
            "url": self.url, "is_subtechnique": self.is_subtechnique,
        }
        if full:
            d["description"] = self.description
        return d


class Analysis(Base):
    __tablename__ = "analyses"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=lambda: dt.datetime.now(dt.timezone.utc))
    source = Column(String(200), default="text")
    preview = Column(String(300), default="")
    results_json = Column(Text, default="[]")
