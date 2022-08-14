import re
from typing import Union

import requests


class MailAuth:
    baseURL = "https://www.googleapis.com"
    querystring = {"key": "AIzaSyDFUC30aJbUREs-vKefE6QmvoVL0qqOv60"}

    headers = {
        "X-Android-Package": "com.tellm.android.app",
        "X-Android-Cert": "A4A8D4D7B09736A0F65596A868CC6FD620920FB0",
        "X-Client-Version": "Android/Fallback/X21000001/FirebaseCore-Android",
    }

    def __init__(self, mail_address, fetch_mail):
        self.mail_address = mail_address
        self.fetch_mail = fetch_mail

    def generate_firebase_token(self):
        self._request_login(self.mail_address)
        print(f"Requested email verification for {self.mail_address}")

        oob_token = re.findall(r'oobCode%3D(\S*)%26continueUrl', self.fetch_mail(self.mail_address))[0]
        print(f"Obtained oob token {oob_token} for email {self.mail_address}")

        firebase_token = self._redeem_oob(oob_token, self.mail_address)
        fresh_token = self._refresh_tokens(firebase_token['refreshToken'])

        return fresh_token

    def _request_login(self, email: str) -> Union[bool, str]:
        url = f"{self.baseURL}/identitytoolkit/v3/relyingparty/getOobConfirmationCode"

        payload = {
            "requestType": 6,
            "email": f"{email}",
            "androidInstallApp": True,
            "canHandleCodeInApp": True,
            "continueUrl": "https://jodel.com/app/magic-link-fallback",
            "androidPackageName": "com.tellm.android.app",
            "androidMinimumVersion": "5.116.0"
        }

        response = requests.post(url=url, json=payload, headers=self.headers, params=self.querystring)

        if response.json()['kind'] == 'identitytoolkit#GetOobConfirmationCodeResponse' and response.status_code == 200:
            return True
        return f"{response.status_code} | Failed to create account | {response.text}"

    def _redeem_oob(self, oobCode: str, email: str) -> Union[str, dict]:
        url = f"{self.baseURL}/identitytoolkit/v3/relyingparty/emailLinkSignin"

        payload = {
            "email": f"{email}",
            "oobCode": f"{oobCode}"
        }

        response = requests.post(url, json=payload, headers=self.headers, params=self.querystring)
        response_jsoned = response.json()

        if response.status_code == 200 and response_jsoned['kind'] == 'identitytoolkit#EmailLinkSigninResponse':
            return {
                'idToken': response_jsoned['idToken'],
                'refreshToken': response_jsoned['refreshToken'],
                'expiresIn': response_jsoned['expiresIn'],
                'localId': response_jsoned['localId'],
            }
        return f"{response.status_code} | Failed to redeem Oob | {response.text}"

    def _refresh_tokens(self, refreshToken: str) -> Union[str, dict]:
        url = "https://securetoken.googleapis.com/v1/token"

        payload = {
            "grantType": "refresh_token",
            "refreshToken": f"{refreshToken}"
        }

        response = requests.post(url, json=payload, headers=self.headers, params=self.querystring)
        response_jsoned = response.json()

        if response.status_code == 200:
            return {
                'access_token': response_jsoned['access_token'],
                'expires_in': response_jsoned['expires_in'],
                'refresh_token': response_jsoned['refresh_token'],
                'user_id': response_jsoned['user_id'],
                'project_id': response_jsoned['project_id']
            }
        return f"{response.status_code} | Failed to refresh tokens | {response.text}"
