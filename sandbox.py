# Sandbox for Agentic AI

class Sandbox:
    def __init__(self, lynx_agent, aegis_agent):
        self.lynx = lynx_agent
        self.aegis = aegis_agent

    def process_request(self, url):
        # Offensive agent crafts a structured attack entry
        attack_entry = self.lynx.attack(url)
        # Defensive agent checks the structured entry
        verdict = self.aegis.inspect_request(url, attack_entry)
        if verdict == 'block':
            return {
                'status': 'blocked',
                'attack': attack_entry,
                'defense': f'Request blocked by Aegis.'
            }
        else:
            return {
                'status': 'allowed',
                'attack': attack_entry,
                'defense': f'Request allowed by Aegis.'
            }

    def process_sequence(self, url: str, count: int = 3, delay: int = 2):
        """Run a sequence of attacks through the sandbox."""
        import time
        results = []
        for i in range(count):
            res = self.process_request(url)
            results.append(res)
            if i < count - 1:
                time.sleep(delay)
        return results
