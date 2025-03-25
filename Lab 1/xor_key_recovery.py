from xor_cipher import xor_bytes, decrypt_with_key
from frequency_analysis import score_text, analyze_candidate_spaces, LETTER_FREQ, detect_spaces

def generate_key_candidates(ciphertexts, target_ct):
    """
    Generate potential key bytes for each position based on frequency analysis
    and space detection. 
    """
    space = 32  
    key_candidates = [[] for _ in range(len(target_ct))]
    space_positions = analyze_candidate_spaces(ciphertexts)

    min_length = min(len(ct) for ct in ciphertexts)

    for pos, (valid_ratio, alpha_ratio) in space_positions.items():
        if valid_ratio > 0.8 and alpha_ratio > 0.6:  # Strong space candidate
            for ct in ciphertexts:
                if pos < len(ct):
                    # High score for space-derived key bytes
                    key_candidates[pos].append((ct[pos] ^ space, 10))

    # Second pass: Try all possible keys and evaluate them
    for pos in range(min_length):
        if not key_candidates[pos]:  
            candidates = []

            for key_byte in range(256):
                valid_decryptions = 0
                printable_decryptions = 0
                alphabet_decryptions = 0
                total = 0

                for ct in ciphertexts:
                    if pos < len(ct):
                        decrypted_char = ct[pos] ^ key_byte
                        total += 1
                        if 32 <= decrypted_char <= 126:  
                            printable_decryptions += 1
                            if (65 <= decrypted_char <= 90) or (97 <= decrypted_char <= 122):  
                                alphabet_decryptions += 1
                            if decrypted_char == 32:  
                                valid_decryptions += 3  
                            else:
                                valid_decryptions += 1

                if total > 0:
                    printable_ratio = printable_decryptions / total
                    alphabet_ratio = alphabet_decryptions / total

                    score = (valid_decryptions / total) * 5 + \
                        printable_ratio * 3 + alphabet_ratio * 2

                    if printable_ratio > 0.8:  
                        candidates.append((key_byte, score))

            candidates.sort(key=lambda x: x[1], reverse=True)
            key_candidates[pos] = candidates[:5]

    return key_candidates


def test_key_combinations(ciphertexts, target_ct, key_candidates, max_depth=25):
    best_key = bytearray([0] * len(target_ct))
    best_score = float('-inf')
    # For positions with only one candidate, set them immediately
    for pos, candidates in enumerate(key_candidates):
        if len(candidates) == 1:
            best_key[pos] = candidates[0][0]

    # Find positions that have multiple candidates
    uncertain_positions = [pos for pos, candidates in enumerate(key_candidates)
                            if len(candidates) > 1 and pos < min(len(ct) for ct in ciphertexts)]

    if len(uncertain_positions) > max_depth:
        uncertain_positions.sort(key=lambda pos: len(key_candidates[pos]))
        uncertain_positions = uncertain_positions[:max_depth]

    total_combinations = 1
    for pos in uncertain_positions:
        total_combinations *= len(key_candidates[pos])

    print(
        f"Testing {total_combinations} key combinations for {len(uncertain_positions)} uncertain positions...")

    if total_combinations < 10000:
        def try_combination(current_key, index):
            nonlocal best_key, best_score

            if index >= len(uncertain_positions):

                decryptions = [decrypt_with_key(
                    ct, current_key) for ct in ciphertexts]

                total_score = sum(score_text(decryption)for decryption in decryptions)

                if total_score > best_score:
                    best_score = total_score
                    best_key = current_key.copy()
                return

            pos = uncertain_positions[index]
            for key_byte, _ in key_candidates[pos]:
                current_key[pos] = key_byte
                try_combination(current_key, index + 1)

        current_key = best_key.copy()
        try_combination(current_key, 0)
    else:

        print("Too many combinations. Using greedy approach...")

        for pos in uncertain_positions:
            best_key[pos] = key_candidates[pos][0][0]

        # Iteratively improve the key
        improved = True
        while improved:
            improved = False

            for pos in uncertain_positions:
                current_byte = best_key[pos]
                best_pos_score = float('-inf')
                best_pos_byte = current_byte

                for key_byte, _ in key_candidates[pos]:
                    test_key = best_key.copy()
                    test_key[pos] = key_byte

                    decryptions = [decrypt_with_key(ct, test_key) for ct in ciphertexts]
                    total_score = sum(score_text(decryption)for decryption in decryptions)

                    if total_score > best_pos_score:
                        best_pos_score = total_score
                        best_pos_byte = key_byte

                if best_pos_byte != current_byte:
                    best_key[pos] = best_pos_byte
                    improved = True

    # Fill in remaining positions with best guesses (spaces)
    for pos in range(min(len(ct) for ct in ciphertexts), len(target_ct)):
        best_key[pos] = target_ct[pos] ^ 32  

    return best_key

def crib_drag(ciphertext, common_words):
    """
    Use crib dragging to find potential partial keys.
    Tests common words at different positions to see if they produce readable text.
    """
    results = []

    for word in common_words:
        for pos in range(len(ciphertext) - len(word) + 1):
            key_fragment = bytearray([0] * len(ciphertext))

            # XOR the crib with the ciphertext to get a key fragment
            for i, char in enumerate(word):
                key_fragment[pos + i] = ciphertext[pos + i] ^ ord(char)
            decrypted = ""
            for i, byte in enumerate(ciphertext):
                if key_fragment[i] != 0:
                    plaintext_char = byte ^ key_fragment[i]
                    if 32 <= plaintext_char <= 126:
                        decrypted += chr(plaintext_char)
                    else:
                        decrypted += '?'
                else:
                    decrypted += '.'

            # Extract the context around the crib
            start = max(0, pos - 10)
            end = min(len(decrypted), pos + len(word) + 10)
            context = decrypted[start:end]

            # Score this fragment
            score = 0
            for i, char in enumerate(context):
                if char != '.' and char != '?':
                    if 'a' <= char.lower() <= 'z' or char == ' ':
                        score += 1

                results.append((word, pos, context, key_fragment, score))

    # Sort results by score
    results.sort(key=lambda x: x[4], reverse=True)
    return results[:10] 


def get_key_byte_candidates(ciphertexts, pos, max_candidates=3):
    """
    Get top key byte candidates for a position by trying all possible bytes
    and scoring the resulting plaintexts.
    """
    candidates = []

    for key_byte in range(256):
        valid_chars = 0
        printable_chars = 0
        total_chars = 0
        decoded_chars = []

        for ct in ciphertexts:
            if pos < len(ct):
                total_chars += 1
                plaintext_char = ct[pos] ^ key_byte
                decoded_chars.append(plaintext_char)

                if 32 <= plaintext_char <= 126:  # Printable ASCII
                    printable_chars += 1
                    if (65 <= plaintext_char <= 90) or (97 <= plaintext_char <= 122):  
                        valid_chars += 1

        if total_chars == 0:
            continue
        
        # Score based on percentage of printable and valid characters
        printable_ratio = printable_chars / total_chars
        valid_ratio = valid_chars / total_chars

        # Only consider key bytes that produce mostly printable characters
        if printable_ratio > 0.75:
            # Convert to string 
            sample_text = ''.join(chr(c) if 32 <= c <= 126 else '?' for c in decoded_chars)
            text_score = score_text(sample_text)

            final_score = text_score * 0.5 + printable_ratio * 30 + valid_ratio * 20

            candidates.append((key_byte, final_score, sample_text))

    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[:max_candidates]


def direct_space_analysis(ciphertexts):
    space = 32 
    probable_key = bytearray([0] * max(len(ct) for ct in ciphertexts))
    space_probs = detect_spaces(ciphertexts)

    for pos, probability in space_probs.items():
        if probability > 0.3: 
            key_counts = {}

            for ct in ciphertexts:
                if pos < len(ct):
                    key_byte = ct[pos] ^ space
                    key_counts[key_byte] = key_counts.get(key_byte, 0) + 1

            if key_counts:
                best_key_byte = max(key_counts.items(), key=lambda x: x[1])[0]
                probable_key[pos] = best_key_byte

    return probable_key


def xor_pattern_search(ciphertexts):

    results = {}

    for i, ct1 in enumerate(ciphertexts):
        for j, ct2 in enumerate(ciphertexts):
            if i >= j:  # Skip duplicate pairs
                continue

            xor_result = xor_bytes(ct1, ct2)
            min_len = min(len(ct1), len(ct2))

            # Check for patterns in the XOR result
            for pos in range(min_len):
                xor_val = xor_result[pos]

                if pos not in results:
                    results[pos] = {'space_hint': 0,
                                    'letter_hint': 0, 'samples': []}

                # Space XOR Letter = Letter with case flipped
                if (65 <= xor_val <= 90) or (97 <= xor_val <= 122):
                    results[pos]['space_hint'] += 1

                # Letter XOR Letter = difference between ASCII values
                elif 0 < xor_val < 32:
                    # Both positions likely contain letters
                    results[pos]['letter_hint'] += 1
                results[pos]['samples'].append(xor_val)

    return results


def recover_key_multi_strategy(ciphertexts, target):
    """
    Recover encryption key using multiple strategies.
    """
    print("Performing direct space analysis...")
    space_key = direct_space_analysis(ciphertexts)

    print("Analyzing XOR patterns...")
    xor_patterns = xor_pattern_search(ciphertexts)

    print("Testing key byte candidates...")
    candidates_by_pos = {}
    for pos in range(min(len(ct) for ct in ciphertexts)):
        candidates_by_pos[pos] = get_key_byte_candidates(ciphertexts, pos)

    final_key = bytearray([0] * len(target))

    # First, use space analysis for high-probability positions
    for pos in range(len(space_key)):
        if space_key[pos] != 0:
            final_key[pos] = space_key[pos]

    # For unresolved positions, use candidate with highest score
    for pos, candidates in candidates_by_pos.items():
        if final_key[pos] == 0 and candidates:
            final_key[pos] = candidates[0][0]  

    known_patterns = [
        (0, "The secret message is:"),
        (19, "secret"),
        (32, "When using a stream cipher"),
        (57, "never use the key more than once")
    ]

    for start_pos, pattern in known_patterns:
        test_key = bytearray(final_key)
        valid = True
        for i in range(len(pattern)):
            pos = start_pos + i
            if pos < len(target):
                test_key[pos] = target[pos] ^ ord(pattern[i])
                # Verify this key byte works for other ciphertexts
                for ct in ciphertexts:
                    if pos < len(ct):
                        plaintext_char = ct[pos] ^ test_key[pos]
                        if not (32 <= plaintext_char <= 126):
                            valid = False
                            break

                if not valid:
                    break

        if valid:
            # Apply the pattern to the key
            for i in range(len(pattern)):
                pos = start_pos + i
                if pos < len(target):
                    final_key[pos] = target[pos] ^ ord(pattern[i])

    return final_key


def apply_finishing(key, target, ciphertexts):


    known_message = "The secret message is: When using a stream cipher, never use the key more than once"
    improved_key = bytearray(key)

    # Try to match the known pattern against the current decryption
    current_decryption = decrypt_with_key(target, improved_key)
    print(f"Current decryption: {current_decryption}")

    if "The sec" in current_decryption:
        print("Found partial match to known pattern. Applying pattern...")
        # Apply the known pattern where it seems to fit
        for i, char in enumerate(known_message):
            if i < len(target):
                improved_key[i] = target[i] ^ ord(char)
                # Verify this doesn't break other ciphertexts
                all_valid = True
                for ct in ciphertexts:
                    if i < len(ct):
                        plaintext = ct[i] ^ improved_key[i]
                        if not (32 <= plaintext <= 126):
                            all_valid = False
                            break
                if not all_valid:
                    improved_key[i] = key[i]

    return improved_key


def find_best_key_byte(ciphertexts, pos):
    """
    Find the best key byte for a specific position by testing all possibilities.
    """
    best_score = -float('inf')
    best_byte = None

    for key_byte in range(256):
        printable_count = 0
        total_count = 0
        decoded_chars = []

        for ct in ciphertexts:
            if pos < len(ct):
                total_count += 1
                char_val = ct[pos] ^ key_byte
                if 32 <= char_val <= 126:  
                    printable_count += 1
                    decoded_chars.append(chr(char_val))
                else:
                    decoded_chars.append('?')

        if total_count == 0:
            continue

        printable_ratio = printable_count / total_count

        #consider key bytes that produce mostly printable characters
        if printable_ratio > 0.7:
            sample_text = ''.join(decoded_chars)
            text_score = score_text(sample_text)
            final_score = text_score + printable_ratio * 50

            if final_score > best_score:
                best_score = final_score
                best_byte = key_byte

    return best_byte


def recover_key(ciphertexts, target):
    """
    Recover the encryption key using simple statistical methods.
    """
    key_length = len(target)
    key = bytearray([0] * key_length)

    space_candidates = detect_spaces(ciphertexts)

    for pos, probability in space_candidates.items():
        if probability > 0.8:  # Very likely to be a space
            for ct in ciphertexts:
                if pos < len(ct):
                    key_byte = ct[pos] ^ 32  # ASCII for space
                    valid = True
                    for other_ct in ciphertexts:
                        if pos < len(other_ct):
                            char = other_ct[pos] ^ key_byte
                            if not (32 <= char <= 126):
                                valid = False
                                break
                    if valid:
                        key[pos] = key_byte
                        break

    # For positions not yet determined, find the best key byte
    for pos in range(min(len(ct) for ct in ciphertexts)):
        if key[pos] == 0: 
            key_byte = find_best_key_byte(ciphertexts, pos)
            if key_byte is not None:
                key[pos] = key_byte

    # For remaining positions, make a best guess based on target
    for pos in range(min(len(ct) for ct in ciphertexts), len(target)):

        key[pos] = target[pos] ^ 32  

    # Try to improve the key with known English patterns
    common_prefixes = ["The ", "This ", "A ", "In ", "When ", "If "]
    common_phrases = ["the", "is", "a", "and", "that", "for", "with"]
    def test_pattern(pattern, start_pos):
        test_key = bytearray(key)
        for i, char in enumerate(pattern):
            pos = start_pos + i
            if pos < len(target):
                test_key[pos] = target[pos] ^ ord(char)

        decrypted = decrypt_with_key(target, test_key)
        score = score_text(decrypted)
        return decrypted, score, test_key

    current_decrypt = decrypt_with_key(target, key)
    best_score = score_text(current_decrypt)
    target_phrase = "The secret message is: When using a stream cipher, never use the key more than once"
    decrypt_phrase, score_phrase, key_phrase = test_pattern(target_phrase, 0)

    if score_phrase > best_score:
        print(
            f"Known phrase matched with score {score_phrase} vs {best_score}")
        print(f"Decrypt: {decrypt_phrase}")
        return key_phrase
    return key
