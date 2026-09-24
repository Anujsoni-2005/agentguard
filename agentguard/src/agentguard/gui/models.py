"""
GUI Guard Data Models — §5.3
"""

from pydantic import BaseModel

class ElementFacts(BaseModel):
    ref: str
    role: str
    name: str
    text: str
    value: str
    attrs: dict[str, str]
    input_type: str | None
    tag: str
    visible: bool
    covered: bool
    opacity: float
    bbox: list[float]
    in_viewport: bool
    ancestors: list[str]
    href_abs: str | None
    form_action: str | None
    form_method: str | None

class PageFacts(BaseModel):
    url: str
    title: str
    epoch: int
    text_taint_level: int
    text_taint_reasons: list[str]
    dialog_open: bool
    tab_count: int
    risky_url: bool

class Snapshot(BaseModel):
    snapshot_id: str
    page: PageFacts
    tree_text: str
    elements: dict[str, ElementFacts]
    screenshot_path: str | None
    taken_at: str
