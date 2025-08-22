import os
import string
from secrets import choice, token_urlsafe

DEFAULT_LEN = 16

def generate_password(length: int = DEFAULT_LEN, use_upper=True, use_lower=True,
                      use_digits=True, use_symbols=True, no_ambiguous=True) -> str:
    alphabet = ""
    if use_lower: alphabet += string.ascii_lowercase
    if use_upper: alphabet += string.ascii_uppercase
    if use_digits: alphabet += string.digits
    if use_symbols: alphabet += "!@#$%^&*()-_=+[]{};:,.?/"
    if no_ambiguous:
        for ch in "O0l1I|`'\"":
            alphabet = alphabet.replace(ch, "")
    if not alphabet:
        alphabet = string.ascii_letters + string.digits
    # ensure at least one from each selected class
    parts = []
    if use_lower: parts.append(choice(string.ascii_lowercase))
    if use_upper: parts.append(choice(string.ascii_uppercase))
    if use_digits: parts.append(choice(string.digits))
    if use_symbols: parts.append(choice("!@#$%^&*()-_=+[]{};:,.?/"))
    # fill the rest
    while len(parts) < max(4, length):
        parts.append(choice(alphabet))
    # trim/shuffle
    import random
    random.shuffle(parts)
    return "".join(parts[:length])
