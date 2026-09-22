from enum import StrEnum

class ImpactClass(StrEnum):
    DELETE = "delete"
    NET_WRITE = "net_write"
    GIT_PUSH = "git_push"
    GUI_STATE_CHANGE = "gui_state_change"
    PROTECTED_WRITE = "protected_write"
    PACKAGE_INSTALL = "package_install"
    PERMISSION_CHANGE = "permission_change"
    FINANCIAL = "financial"
