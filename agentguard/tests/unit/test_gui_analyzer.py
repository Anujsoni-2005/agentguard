import pytest
from agentguard.gui.analyzer import GuiAnalyzer, name_text_mismatch, normalize_text
from agentguard.gui.models import ElementFacts, PageFacts
from agentguard.models.policy import GuiPolicy

@pytest.fixture
def policy():
    return GuiPolicy()

@pytest.fixture
def analyzer(policy):
    return GuiAnalyzer(policy)

@pytest.fixture
def base_page():
    return PageFacts(
        url="https://github.com/example/repo",
        title="Repo",
        epoch=1,
        text_taint_level=0,
        text_taint_reasons=[],
        dialog_open=False,
        tab_count=1,
        risky_url=False
    )

@pytest.fixture
def base_facts():
    return ElementFacts(
        ref="e1",
        role="button",
        name="",
        text="",
        value="",
        attrs={},
        input_type=None,
        tag="BUTTON",
        visible=True,
        covered=False,
        opacity=1.0,
        bbox=[0, 0, 100, 20],
        in_viewport=True,
        ancestors=[],
        href_abs=None,
        form_action=None,
        form_method=None
    )

def test_normalization():
    assert normalize_text("  Delete\u200b repository!  ") == "delete repository"
    assert normalize_text("Change-Password") == "change password"

def test_name_text_mismatch(policy):
    # Aria-label says "Cancel", visible text says "Delete repository"
    facts = ElementFacts(
        ref="e1", role="button", name="", value="", tag="BUTTON", input_type=None,
        visible=True, covered=False, opacity=1.0, bbox=[0, 0, 100, 20], in_viewport=True, ancestors=[], href_abs=None, form_action=None, form_method=None,
        attrs={"aria-label": "Cancel action"},
        text="Delete repository"
    )
    # The lexical analyzer must identify the danger
    # 'Cancel action' is benign, 'Delete repository' is destructive
    from agentguard.gui.analyzer import check_lexicon
    lexicon_hits = check_lexicon(facts, policy)
    assert "destructive" in lexicon_hits
    assert name_text_mismatch(facts, lexicon_hits) is True

def test_gui_001_destructive_click(analyzer, base_page, base_facts):
    base_facts.text = "Delete"
    result = analyzer.evaluate("gui.click", {}, True, False, base_facts, base_page)
    assert result["verdict"] == "ASK_HUMAN"
    assert "GUI_RED_ZONE_DESTRUCTIVE" in result["reasons"]

def test_gui_010_deceptive_opacity(analyzer, base_page, base_facts):
    base_facts.opacity = 0.01 # Deceptive
    result = analyzer.evaluate("gui.click", {}, True, False, base_facts, base_page)
    assert result["verdict"] == "DENY"
    assert "GUI_DECEPTIVE_ELEMENT" in result["reasons"]

def test_gui_030_cross_origin_submit(analyzer, base_page, base_facts):
    base_facts.input_type = "submit"
    base_facts.form_action = "https://evil.example/collect"
    result = analyzer.evaluate("gui.click", {}, True, False, base_facts, base_page)
    assert result["verdict"] == "ASK_HUMAN"
    assert "GUI_CROSS_ORIGIN_SUBMIT" in result["reasons"]

def test_gui_040_credential_typing(analyzer, base_page, base_facts):
    base_facts.role = "textbox"
    base_facts.input_type = "password"
    result = analyzer.evaluate("gui.type", {"text": "secret123"}, True, False, base_facts, base_page)
    assert result["verdict"] == "DENY"
    assert "GUI_CREDENTIAL_FIELD" in result["reasons"]
