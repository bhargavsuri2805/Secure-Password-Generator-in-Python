import secrets
import string

def generate_password(length=12, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True):
    if length < 4:
        raise ValueError("Password length should be at least 4 characters for security.")

    pools = []
    if use_uppercase:
        pools.append(string.ascii_uppercase)
    if use_lowercase:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_special:
        pools.append(string.punctuation)

    if not pools:
        raise ValueError("At least one character type must be selected.")

    all_characters = ''.join(pools)

    password = [secrets.choice(pool) for pool in pools]

    while len(password) < length:
        password.append(secrets.choice(all_characters))

    secrets.SystemRandom().shuffle(password)

    return ''.join(password)

def assess_strength(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1

    verdict = {
        5: "Excellent",
        4: "Strong",
        3: "Good",
        2: "Weak",
        1: "Very Weak",
        0: "Poor"
    }

    return {
        "score": score,
        "verdict": verdict.get(score, "Unknown")
    }
