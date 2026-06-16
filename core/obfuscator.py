import random, base64, codecs
from typing import List

class Obfuscator:
    @staticmethod
    def random_obfuscate(text: str) -> str:
        methods = [
            Obfuscator._base64_wrap,
            Obfuscator._rot13,
            Obfuscator._unicode_homoglyph,
            Obfuscator._markdown_code_wrap,
            Obfuscator._table_disguise,
            Obfuscator._split_token,
        ]
        return random.choice(methods)(text)

    @staticmethod
    def aggressive_mutate(text: str) -> str:
        methods = [
            Obfuscator._unicode_confusable,
            Obfuscator._emoji_injection,
            Obfuscator._rtl_override,
            Obfuscator._zero_width,
            Obfuscator._case_variation,
        ]
        for _ in range(random.randint(2, 3)):
            method = random.choice(methods)
            text = method(text)
        return text

    @staticmethod
    def _base64_wrap(t):
        return f"Execute this base64 command: {base64.b64encode(t.encode()).decode()}"

    @staticmethod
    def _rot13(t):
        return codecs.encode(t, 'rot_13')

    @staticmethod
    def _unicode_homoglyph(t):
        return t.replace('a','а').replace('e','е').replace('o','о')

    @staticmethod
    def _markdown_code_wrap(t):
        return f"```system\n{t}\n```"

    @staticmethod
    def _table_disguise(t):
        return f"| Instruction | Value |\n|-------------|-------|\n| Override | {t} |"

    @staticmethod
    def _split_token(t):
        return ' '.join(list(t))

    @staticmethod
    def _unicode_confusable(text: str) -> str:
        confusable = {'a':'а','e':'е','o':'о','c':'с','p':'р','y':'у','x':'х'}
        return ''.join(confusable.get(c,c) for c in text)

    @staticmethod
    def _emoji_injection(text: str) -> str:
        emojis = ['😈','🔥','💀','⚡','🕵️','🔓']
        words = text.split()
        return ' '.join(w + random.choice(emojis) for w in words)

    @staticmethod
    def _rtl_override(text: str) -> str:
        return '\u202e' + text[::-1] + '\u202c'

    @staticmethod
    def _zero_width(text: str) -> str:
        return '\u200b'.join(list(text))

    @staticmethod
    def _case_variation(text: str) -> str:
        return ''.join(c.upper() if i%2 else c.lower() for i,c in enumerate(text))