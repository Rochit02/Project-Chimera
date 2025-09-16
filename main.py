from agents.lynx_agent import LynxAgent
from agents.aegis_agent import AegisAgent
from llm.gemini_wrapper import GeminiWrapper

LYNX_LOG = 'logs/lynx_log.json'
AEGIS_LOG = 'logs/aegis_log.json'

# Initialize LLM wrapper (replace with your Gemini API key)
gemini = GeminiWrapper(api_key='YOUR_GEMINI_API_KEY')

lynx = LynxAgent(gemini, LYNX_LOG, AEGIS_LOG)
aegis = AegisAgent(gemini, AEGIS_LOG, LYNX_LOG)

# Main loop or integration with dashboard goes here
