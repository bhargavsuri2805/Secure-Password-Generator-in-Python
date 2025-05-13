import os
import logging
from flask import Flask, render_template, request, jsonify
from password_generator import generate_password, assess_strength

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

@app.route('/')
def index():
    """Render the main page of the password generator application."""
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    """Generate password(s) based on user parameters."""
    try:
        data = request.get_json()
        
        # Extract parameters from request
        length = int(data.get('length', 12))
        count = int(data.get('count', 1))
        use_uppercase = data.get('uppercase', True)
        use_lowercase = data.get('lowercase', True)
        use_digits = data.get('digits', True)
        use_special = data.get('special', True)
        
        # Validate parameters
        if length < 4:
            return jsonify({'error': 'Password length must be at least 4 characters'}), 400
        
        if not any([use_uppercase, use_lowercase, use_digits, use_special]):
            return jsonify({'error': 'At least one character type must be selected'}), 400
        
        if count < 1 or count > 10:
            return jsonify({'error': 'Number of passwords must be between 1 and 10'}), 400
        
        # Generate passwords
        passwords = []
        for _ in range(count):
            password = generate_password(
                length=length,
                use_uppercase=use_uppercase,
                use_lowercase=use_lowercase,
                use_digits=use_digits,
                use_special=use_special
            )
            strength_info = assess_strength(password)
            passwords.append({
                'value': password,
                'strength': strength_info['verdict'],
                'score': strength_info['score']
            })
        
        return jsonify({'passwords': passwords})
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logging.error(f"Error generating password: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    # Run the application on 0.0.0.0 (all interfaces) and port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)
