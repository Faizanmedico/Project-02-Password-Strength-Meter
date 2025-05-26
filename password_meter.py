import re

def evaluate_password_strength(password):
    """
    Evaluates the strength of a given password based on various security rules.
    Assigns a strength score and provides feedback for improvement.
    """
    score = 0
    feedback = []

    # --- Rule 1: Length ---
    if len(password) >= 12:
        score += 3
        feedback.append("👍 لمبائی اچھی ہے (کم از کم 12 حروف تجویز کیے جاتے ہیں).")
    elif len(password) >= 8:
        score += 2
        feedback.append("👌 لمبائی بہتر کی جا سکتی ہے (کم از کم 12 حروف تجویز کیے جاتے ہیں).")
    else:
        score += 1
        feedback.append("⚠️ پاس ورڈ بہت چھوٹا ہے (کم از کم 8 حروف، 12 حروف تجویز کیے جاتے ہیں).")

    # --- Rule 2: Character Types ---
    has_lowercase = bool(re.search(r'[a-z]', password))
    has_uppercase = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()-_+=~`\[\]{}|\\:;"\'<>,.?/]', password))

    char_types_count = sum([has_lowercase, has_uppercase, has_digit, has_special])

    if char_types_count == 4:
        score += 4
        feedback.append("👍 تمام قسم کے حروف (چھوٹے، بڑے، ہندسے، خاص حروف) شامل ہیں.")
    elif char_types_count == 3:
        score += 3
        feedback.append("👌 تقریباً تمام قسم کے حروف شامل ہیں.")
    elif char_types_count == 2:
        score += 2
        feedback.append("⚠️ مزید قسم کے حروف شامل کریں (مثلاً، خاص حروف یا ہندسے).")
    else:
        score += 1
        feedback.append("❗ بہت کم قسم کے حروف استعمال ہوئے ہیں (چھوٹے/بڑے حروف، ہندسے، خاص حروف شامل کریں).")

    # --- Rule 3: Common Patterns and Sequences ---
    # Common sequences (e.g., '123', 'abc')
    if re.search(r'123|abc|password|qwerty|admin', password, re.IGNORECASE):
        score -= 2 # Deduct score for common patterns
        feedback.append("⛔ عام پیٹرن یا الفاظ (جیسے '123' یا 'password') استعمال کرنے سے گریز کریں.")

    # Repeating characters (e.g., 'aaa')
    if re.search(r'(.)\1\1', password):
        score -= 1
        feedback.append("⚠️ مسلسل دہرائے جانے والے حروف (جیسے 'aaa') استعمال نہ کریں.")

    # Keyboard patterns (e.g., 'asdf') - basic check
    keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456', 'edcrfv', 'tgbyhn']
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            score -= 1
            feedback.append(f"⚠️ کی بورڈ پیٹرن '{pattern}' استعمال کرنے سے گریز کریں.")
            break # Only deduct once for any keyboard pattern

    # --- Determine Strength Level ---
    strength = ""
    if score >= 7:
        strength = "بہت مضبوط (Very Strong)"
    elif score >= 5:
        strength = "مضبوط (Strong)"
    elif score >= 3:
        strength = "اوسط (Moderate)"
    else:
        strength = "کمزور (Weak)"

    return strength, score, feedback

def main():
    """
    Main function to run the password strength meter application.
    """
    st.set_page_config(page_title="پاس ورڈ کی طاقت کا میٹر", page_icon="🔐")
    st.title("🔐 پاس ورڈ کی طاقت کا میٹر")
    st.markdown("اپنے پاس ورڈ کی طاقت کو جانچیں اور بہتر بنانے کے لیے تجاویز حاصل کریں۔")

    password = st.text_input("اپنا پاس ورڈ یہاں درج کریں:", type="password")

    if password:
        strength, score, feedback = evaluate_password_strength(password)

        st.subheader("پاس ورڈ کی طاقت:")
        if strength == "بہت مضبوط (Very Strong)":
            st.success(f"**{strength}** (اسکور: {score}/11)")
        elif strength == "مضبوط (Strong)":
            st.success(f"**{strength}** (اسکور: {score}/11)")
        elif strength == "اوسط (Moderate)":
            st.warning(f"**{strength}** (اسکور: {score}/11)")
        else:
            st.error(f"**{strength}** (اسکور: {score}/11)")

        st.subheader("بہتری کے لیے تجاویز:")
        for item in feedback:
            st.write(item)
    else:
        st.info("پاس ورڈ کی طاقت جانچنے کے لیے اپنا پاس ورڈ درج کریں۔")

    st.markdown("---")
    st.caption("ایک سادہ پاس ورڈ سٹرینتھ میٹر، مزید جدید جانچ کے لیے اضافی قواعد شامل کیے جا سکتے ہیں.")

if __name__ == "__main__":
    # If using Streamlit, uncomment the line below and run with `streamlit run your_script_name.py`
    # import streamlit as st
    # main()

    # For console-based testing, uncomment these lines:
    print("پاس ورڈ کی طاقت کا میٹر")
    while True:
        password = input("اپنا پاس ورڈ درج کریں (باہر نکلنے کے لیے 'exit' لکھیں): ")
        if password.lower() == 'exit':
            break
        strength, score, feedback = evaluate_password_strength(password)
        print(f"\nپاس ورڈ کی طاقت: {strength} (اسکور: {score}/11)")
        print("بہتری کے لیے تجاویز:")
        for item in feedback:
            print(f"- {item}")
        print("-" * 30)