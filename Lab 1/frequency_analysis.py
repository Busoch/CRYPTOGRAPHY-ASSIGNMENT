import binascii

# Letter, word, and bigram frequency dictionaries
LETTER_FREQ = {
    'e': 12.0, 't': 9.1, 'a': 8.12, 'o': 7.68, 'i': 7.31, 'n': 6.95, 's': 6.28,
    'r': 6.02, 'h': 5.92, 'd': 4.32, 'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61,
    'f': 2.3, 'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49, 'v': 1.11,
    'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.10, 'z': 0.07
}

COMMON_WORDS = {
    "the": 20, "be": 15, "to": 15, "of": 15, "and": 14, "a": 14, "in": 13,
    "that": 12, "have": 11, "it": 10, "for": 10, "not": 10, "on": 9, "with": 9,
    "he": 9, "as": 8, "you": 8, "do": 8, "at": 8, "this": 8, "but": 8, "his": 7,
    "by": 7, "from": 7, "they": 7, "we": 7, "say": 7, "her": 6, "she": 6, "or": 6
}

COMMON_BIGRAMS = {
    "th": 10, "he": 10, "in": 9, "er": 9, "an": 8, "re": 8, "on": 8, "at": 7,
    "en": 7, "nd": 7, "ti": 7, "es": 7, "or": 7, "to": 6, "of": 6, "ed": 6, "is": 6
}


def score_text(text):
    """
    Score text based on English character frequency.
    Higher score = more likely valid English.
    """
    text = text.lower()
    return sum(
        LETTER_FREQ.get(char, 0) if 'a' <= char <= 'z' else
        15 if char == ' ' else
        2 if char in ',.!?;:\'"-()' else
        1 if char.isdigit() else
        -50 if not (32 <= ord(char) <= 126) else 0
        for char in text
    )


def detect_spaces(ciphertexts):
    """
    Detect likely space positions in XOR-encrypted ciphertexts.
    Returns a dictionary of position-to-space probability.
    """
    space_candidates = {}
    min_len = min(map(len, ciphertexts))

    for pos in range(min_len):
        valid_count, total_tests = 0, 0

        for i, ct1 in enumerate(ciphertexts):
            key_byte = ct1[pos] ^ 32  

            for j, ct2 in enumerate(ciphertexts):
                if i != j and pos < len(ct2):
                    plaintext = ct2[pos] ^ key_byte
                    if 32 <= plaintext <= 126:
                        valid_count += 1
                    total_tests += 1

        if total_tests:
            space_candidates[pos] = valid_count / total_tests

    return space_candidates


def analyze_candidate_spaces(ciphertexts):
    """
    Analyze candidate space positions in ciphertexts based on likely plaintext characters.
    Returns a dictionary of position-to-score (valid_chars_ratio, alphabet_chars_ratio).
    """
    space_candidates = {}
    min_len = min(map(len, ciphertexts))

    for pos in range(min_len):
        space_scores = []

        for i, ct1 in enumerate(ciphertexts):
            key_byte = ct1[pos] ^ 32  
            valid_chars, alphabet_chars = 0, 0

            for j, ct2 in enumerate(ciphertexts):
                if i == j or pos >= len(ct2):
                    continue

                decrypted_char = ct2[pos] ^ key_byte
                if 32 <= decrypted_char <= 126:
                    valid_chars += 1
                    if decrypted_char.isalpha():
                        alphabet_chars += 1

            total_others = sum(1 for x in ciphertexts if x != ct1 and pos < len(x))
            if total_others:
                space_scores.append((valid_chars / total_others, alphabet_chars / total_others))

        if space_scores:
            avg_valid = sum(score[0] for score in space_scores) / len(space_scores)
            avg_alphabet = sum(score[1] for score in space_scores) / len(space_scores)
            space_candidates[pos] = (avg_valid, avg_alphabet)

    return space_candidates
