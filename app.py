# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=line-too-long

import os
import hmac
import json
import base64
import logging

from dotenv import load_dotenv

from flask import Flask, request

logging.basicConfig(level=logging.DEBUG)

load_dotenv()

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def webhook():
    body = request.json
    logging.debug('body: %s', body)

    if 'x-prime-trust-webhook-hmac' in request.headers:

        logging.info('x-prime-trust-webhook-hmac: %s', request.headers['x-prime-trust-webhook-hmac'])

        webhook_shared_secret = os.getenv('WEBHOOK_SHARED_SECRET')
        signature = hmac.new(key=webhook_shared_secret.encode(), msg=json.dumps(body).encode(), digestmod='sha256')
        b64_signature = base64.b64encode(signature.digest()).decode()
        logging.info('           calculated hmac: %s', b64_signature)

        if b64_signature != request.headers['x-prime-trust-webhook-hmac']:
            logging.warning('hmac mismatch')
            return {'error':'hmac mismatch'}, 400

        logging.info('hmac matches')

    return body, 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
