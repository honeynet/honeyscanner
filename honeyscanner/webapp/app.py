from flask import Flask, request, jsonify
from honeyscanner.main import main as honeyscanner_main
import sys
import os
import tempfile

app = Flask(__name__)

@app.route('/api/run', methods=['POST'])
def run():
    config = request.json['config']
    honeypot_type = request.json['honeypot_type']

    # Save config to a temporary file
    config_file = tempfile.NamedTemporaryFile(delete=False)
    config_file.write(config.encode())
    config_file.close()

    # Run honeyscanner
    sys.argv = ['', '--config', config_file.name, '--honeypot', honeypot_type]
    report = honeyscanner_main()

    # Remove the temporary file
    os.unlink(config_file.name)

    return jsonify(report)

if __name__ == '__main__':
    app.run(debug=True)
