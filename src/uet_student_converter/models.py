"""Data models used during conversion."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StudentRecord:
    """A student record extracted from the source PDF."""

    source_stt: int
    mssv: str
    name: str
    date_of_birth: str
    gender: str
    major: str
    class_code: str

    @property
    def account(self) -> str:
        """Return the account address derived from the MSSV."""

        return f"{self.mssv}@vnu.edu.vn"

    @property
    def password(self) -> str:
        """Return the DDMMYYYY password with all eight characters preserved."""

        return self.date_of_birth.replace("/", "")
