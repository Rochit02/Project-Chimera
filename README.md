# Agentic AI Hackathon Project

## Overview
Two agentic AIs (Lynx - offensive, Aegis - defensive) compete and learn using Google Gemini LLM. Dashboard monitors progress and allows URL input.

## Structure
- `agents/`: AI agent classes
- `logs/`: Agent logs
- `llm/`: Gemini LLM wrapper
- `dashboard/`: Flask dashboard
- `main.py`: Entry point

## Setup
1. Install requirements: `pip install -r requirements.txt`
2. Add your Gemini API key in `main.py`
3. Run dashboard: `python dashboard/app.py`
