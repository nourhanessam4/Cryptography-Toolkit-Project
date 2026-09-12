# import the main liberaies and algos
import streamlit as st
import base64
import hashlib
import urllib.parse
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

st.set_page_config(page_title="Crypto Toolkit", layout="wide")
st.title("Crypto Toolkit Project")
st.markdown("### Cryptographic Operations Tool")


# Helper Functions 
def get_key(key: str, length: int):
    return hashlib.sha256((key + "CryptoProject_Secure_Salt_2024").encode()).digest()[:length]


def encrypt_sym(algo: str, text: str, key: str) -> str:
    data = text.encode()
    if algo == "AES":
        k = get_key(key, 32)
        cipher = AES.new(k, AES.MODE_CBC)
        iv = cipher.iv
    elif algo == "DES":
        k = get_key(key, 8)
        cipher = DES.new(k, DES.MODE_CBC)
        iv = cipher.iv
    else:  # 3DES
        k = DES3.adjust_key_parity(get_key(key, 24))
        cipher = DES3.new(k, DES3.MODE_CBC)
        iv = cipher.iv
    ct = cipher.encrypt(pad(data, cipher.block_size))
    return base64.b64encode(iv + ct).decode()


def decrypt_sym(algo: str, encrypted: str, key: str) -> str:
    try:
        raw = base64.b64decode(encrypted)
        if algo == "AES":
            iv, ct = raw[:16], raw[16:]
            cipher = AES.new(get_key(key, 32), AES.MODE_CBC, iv)
        elif algo == "DES":
            iv, ct = raw[:8], raw[8:]
            cipher = DES.new(get_key(key, 8), DES.MODE_CBC, iv)
        else:
            iv, ct = raw[:8], raw[8:]
            cipher = DES3.new(DES3.adjust_key_parity(get_key(key, 24)), DES3.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), cipher.block_size).decode()
    except Exception:
        return "Decryption Failed (Wrong key or corrupted data)"


#  RSA 
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()


# Default Key for Symmetric
DEFAULT_KEY = "MySecretKey12345"

# Main Tabs 
tab1, tab2, tab3, tab4 = st.tabs([
    "Symmetric Encryption",
    "RSA Asymmetric",
    "Encoding & Decoding",
    "Hashing"
])

# Tab 1: Symmetric
with tab1:
    st.subheader("Symmetric Encryption (AES, DES, 3DES)")
    st.markdown("Encrypt and decrypt text using symmetric algorithms.")
    col1, col2 = st.columns(2, gap="large")
    with col1:
        st.markdown("**Encryption**")
        plain_text = st.text_area("Enter Plain Text", height=170, key="plain_sym")
        use_default = st.checkbox("Use Default Key", value=True, help=f"Default Key: {DEFAULT_KEY}")
        if use_default:
            secret_key = DEFAULT_KEY
            st.info(f"Using Default Key: `{DEFAULT_KEY}`")
        else:
            secret_key = st.text_input("Enter Secret Key", type="password", key="key_sym")
        algo = st.selectbox("Select Algorithm", ["AES", "DES", "3DES"], key="algo_sym")
        if st.button("Encrypt", type="primary", use_container_width=True):
            if plain_text and secret_key:
                result = encrypt_sym(algo, plain_text, secret_key)
                st.success("Encryption completed successfully")
                st.code(result, language=None)  

    with col2:
        st.markdown("**Decryption**")
        enc_text = st.text_area("Enter Encrypted Text (Base64)", height=170, key="enc_sym")
        if st.button("Decrypt", type="primary", use_container_width=True):
            if enc_text and secret_key:
                result = decrypt_sym(algo, enc_text, secret_key)
                if "Failed" in result:
                    st.error(result)
                else:
                    st.success("Decryption completed successfully")
                    st.code(result, language=None)  

# Tab 2: RSA 
with tab2:
    st.subheader("RSA Asymmetric Encryption (2048-bit)")
    st.markdown("Secure encryption using public and private keys.")

    if "rsa_keys" not in st.session_state:
        st.session_state.rsa_keys = generate_rsa_keys()
    if st.button("Generate New RSA Keys", use_container_width=True):
        st.session_state.rsa_keys = generate_rsa_keys()
        st.success("New RSA keys generated successfully!")
    private_key, public_key = st.session_state.rsa_keys

    st.info("Keys are generated and managed internally for security.")
    st.divider()

    col3, col4 = st.columns(2, gap="large")
    with col3:
        text_to_encrypt = st.text_area("Text to Encrypt", height=140)
        if st.button("Encrypt with Public Key", type="primary", use_container_width=True):
            if text_to_encrypt:
                try:
                    cipher = PKCS1_OAEP.new(public_key)
                    encrypted = base64.b64encode(cipher.encrypt(text_to_encrypt.encode())).decode()
                    st.success("Encryption successful")
                    st.code(encrypted, language=None)  
                except:
                    st.error("Text is too long for RSA encryption")
    with col4:
        text_to_decrypt = st.text_area("Encrypted Text to Decrypt", height=140)
        if st.button("Decrypt with Private Key", type="primary", use_container_width=True):
            if text_to_decrypt:
                try:
                    cipher = PKCS1_OAEP.new(private_key)
                    decrypted = cipher.decrypt(base64.b64decode(text_to_decrypt)).decode()
                    st.success("Decryption successful")
                    st.code(decrypted, language=None)  
                except:
                    st.error("Decryption failed - Invalid data")

# Tab 3: Encoding 
with tab3:
    st.subheader("Encoding & Decoding")
    st.markdown("Convert text between different encoding formats.")
    input_text = st.text_area("Input Text", height=160)
    method = st.radio("Select Method", ["Base64", "Hex", "URL Encoding"], horizontal=True)
    col1, col2 = st.columns(2, gap="large")
    with col1:
        if st.button("Encode", type="primary", use_container_width=True):
            if method == "Base64":
                result = base64.b64encode(input_text.encode()).decode()
            elif method == "Hex":
                result = input_text.encode().hex()
            else:
                result = urllib.parse.quote(input_text)
            st.success("Encoding completed")
            st.code(result, language=None)  
    with col2:
        if st.button("Decode", type="primary", use_container_width=True):
            try:
                if method == "Base64":
                    result = base64.b64decode(input_text).decode()
                elif method == "Hex":
                    result = bytes.fromhex(input_text).decode()
                else:
                    result = urllib.parse.unquote(input_text)
                st.success("Decoding completed")
                st.code(result, language=None) 
            except Exception as e:
                st.error(f"Decoding Error: {e}")

# Tab 4: Hashing 
with tab4:
    st.subheader("Hashing (SHA-256 & SHA-512)")
    st.markdown("Generate secure hashes with optional salt.")
    input_text = st.text_area("Input Text for Hashing", height=150)
    hash_algo = st.selectbox("Hash Algorithm", ["SHA-256", "SHA-512"])
    st.markdown("**Salt Options**")
    salt_option = st.radio("Choose Salt Type:",
                           ["Use Random Salt (Recommended)",
                            "Custom Salt",
                            "No Salt"], horizontal=True)
    custom_salt = ""
    if salt_option == "Custom Salt":
        custom_salt = st.text_input("Enter Custom Salt", placeholder="Enter your salt here...")
    if st.button("Generate Hash", type="primary", use_container_width=True):
        if input_text:
            salt_display = "None"
            if salt_option == "Use Random Salt (Recommended)":
                salt = get_random_bytes(16)
                salt_display = salt.hex()
                data = salt + input_text.encode()
                st.info(f"**Generated Salt (hex):** {salt_display}")
            elif salt_option == "Custom Salt" and custom_salt:
                salt_display = custom_salt
                data = custom_salt.encode() + input_text.encode()
            else:
                data = input_text.encode()
            h = hashlib.sha256() if hash_algo == "SHA-256" else hashlib.sha512()
            h.update(data)
            final_hash = h.hexdigest()
            st.success("Hash generated successfully")
            st.code(f"Algorithm : {hash_algo}\n"
                    f"Salt : {salt_display}\n"
                    f"Hash : {final_hash}", language=None)
        else:
            st.warning("Please enter text to hash.")
