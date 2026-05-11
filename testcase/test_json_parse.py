"""
Test the extractNestedJsonValue logic manually
"""

def extractNestedJsonValue(json, outerKey, innerKey):
    outerSearchKey = '"' + outerKey + '"'
    outerPos = json.find(outerSearchKey)
    if outerPos == -1: return ""
    
    bracePos = json.find("{", outerPos)
    if bracePos == -1: return ""
    
    # Find the end of this nested object
    braceEnd = bracePos + 1
    depth = 1
    while braceEnd < len(json) and depth > 0:
        if json[braceEnd] == '{': depth += 1
        elif json[braceEnd] == '}': depth -= 1
        braceEnd += 1
    
    nestedJson = json.substr(bracePos, braceEnd - bracePos) if hasattr(json, 'substr') else json[bracePos:braceEnd]
    return extractJsonValue(nestedJson, innerKey)

def extractJsonValue(json, key):
    searchKey = '"' + key + '"'
    pos = json.find(searchKey)
    if pos == -1: return ""
    
    pos = json.find(":", pos)
    if pos == -1: return ""
    
    pos += 1
    while pos < len(json) and (json[pos] in ' \t\n\r'): pos += 1
    
    if pos < len(json) and json[pos] != '"':
        endPos = json.find_first_of(",}\n", pos) if hasattr(json, 'find_first_of') else min(json.find(",", pos), json.find("}", pos), json.find("\n", pos))
        if endPos == -1: endPos = len(json)
        return json[pos:endPos].strip()
    
    quoteStart = pos
    endPos = json.find('"', quoteStart + 1)
    if endPos == -1: return ""
    
    return json[quoteStart + 1:endPos]

# Test with actual keys.json content
keys_json = open(r"G:\workspaces\git\corssmool\crossmool\testcase\keys\cpp\keys.json").read()
print("Keys JSON length:", len(keys_json))

enc_pub = extractNestedJsonValue(keys_json, "encryption_public_key", "hex")
print(f"encryption_public_key.hex: {enc_pub[:40]}..." if enc_pub else "encryption_public_key.hex: EMPTY")

sign_priv = extractNestedJsonValue(keys_json, "signature_private_key", "hex")
print(f"signature_private_key.hex: {sign_priv[:40]}..." if sign_priv else "signature_private_key.hex: EMPTY")

# Now test with Java keys
java_keys = open(r"G:\workspaces\git\corssmool\crossmool\testcase\keys\java\keys.json").read()
enc_pub2 = extractNestedJsonValue(java_keys, "encryption_public_key", "hex")
print(f"\nJava encryption_public_key.hex: {enc_pub2[:40]}..." if enc_pub2 else "Java encryption_public_key.hex: EMPTY")
