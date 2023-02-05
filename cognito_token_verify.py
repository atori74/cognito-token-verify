import base64
import json
import os

from jose import jwt, jwk
from jose.utils import base64url_decode
import requests



# Refer: https://github.com/awslabs/aws-support-tools/blob/master/Cognito/decode-verify-jwt/decode-verify-jwt.py

def get_access_token(client_id, client_secret, token_endpoint):
    authorization = base64.b64encode(f'{client_id}:{client_secret}'.encode('utf-8')).decode()
    
    headers = {
        'Authorization': f'Basic {authorization}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id
    }
    res = requests.post(f'{token_endpoint}/oauth2/token', headers=headers, data=payload)
    if res.status_code != 200:
        return None
    
    return res.json()['access_token']


def lambda_handler(event, context):
    CLIENT_ID = os.environ['CLIENT_ID']
    CLIENT_SECRET = os.environ['CLIENT_SECRET']
    TOKEN_ENDPOINT = os.environ['TOKEN_ENDPOINT']
    USERPOOL_ID = os.environ['USERPOOL_ID']
    
    print('### Cognitoアクセストークンの取得とクレームの検証シミュレート ###')
    print(f'CLIENT_ID: {CLIENT_ID}')
    print(f'CLIENT_SECRET: {CLIENT_SECRET}')
    print(f'TOKEN_ENDPOINT: {TOKEN_ENDPOINT}')
    print()
    
    
    print('### アクセストークンの取得 ###')
    access_token = get_access_token(CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT)
    print('ACCESS_TOKEN:')
    if access_token is None:
        print('アクセストークンの取得に失敗しました')
        return False
    print(access_token)
    print()
    
    
    print('### JSON Webキーの取得 ###')
    headers = jwt.get_unverified_headers(access_token)
    kid = headers['kid']
    keys_url = f'https://cognito-idp.ap-northeast-1.amazonaws.com/{USERPOOL_ID}/.well-known/jwks.json'
    res = requests.get(keys_url)
    keys = res.json()['keys']
    public_key = None
    for key in keys:
        if key['kid'] == kid: public_key = jwk.construct(key)
    print('JWK:')
    print(key)
    print()
    
    
    print('### アクセストークンの検証 ###')
    message, encoded_signature = str(access_token).rsplit('.', 1)
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return False
    print('Signature successfully verified')
    print()
    
    
    print('### アクセストークンからクレームの取得 ###')
    claims = jwt.get_unverified_claims(access_token)
    print('CLAIMS:')
    print(claims)
    print()
    
    return True

if __name__ == '__main__':
    lambda_handler(None, None)
