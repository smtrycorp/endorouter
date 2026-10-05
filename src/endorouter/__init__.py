"""endorouter: decide where a prompt may go before deciding which model is best."""

from .config import Config, ConfigError, Target, load_config
from .labels import Label
from .policy import Decision, decide

__version__ = "0.2.0"
POLICY_VERSION = "1"

__all__ = ["Config", "ConfigError", "Target", "load_config", "Label", "Decision", "decide", "__version__", "POLICY_VERSION"]
