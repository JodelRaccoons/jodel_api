import random
import re
import string
import time
from typing import Union

import requests
import bs4


class MailAuth:
    baseURL = "https://www.googleapis.com"
    querystring = {"key": "AIzaSyDFUC30aJbUREs-vKefE6QmvoVL0qqOv60"}

    headers = {
        "X-Android-Package": "com.tellm.android.app",
        "X-Android-Cert": "A4A8D4D7B09736A0F65596A868CC6FD620920FB0",
        "X-Client-Version": "Android/Fallback/X21000001/FirebaseCore-Android",
    }

    def generate_firebase_token(self):
        email = f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=16))}@eyepaste.com"
        self._requestLogin(email)

        print(f"Requested email verification for {email}")

        oobToken = None
        while not oobToken:
            response = bs4.BeautifulSoup(requests.get(f"https://www.eyepaste.com/inbox/{email}").text.replace("\r", "").replace("\n", "").replace("=", ""), features="html.parser").get_text()
            oobCodes = re.findall('oobCode%3D(\S*)%26continueUrl', response)
            if len(oobCodes) > 0:
                oobToken = oobCodes[0]
            else:
                time.sleep(1)

        print(f"Obtained oob token {oobToken} for email {email}")

        firebase_token = self._redeem_oob(oobToken, email)

        fresh_token = self._refreshTokens(firebase_token['refreshToken'])

        return fresh_token['access_token']

    def _requestLogin(self, email: str) -> Union[bool, str]:
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

    def _extract_oob(self, link: str) -> Union[bool, str]:
        try:
            url = requests.utils.unquote(link)
            start = 'oobCode='
            end = '&continueUrl'
            return (url[url.find(start) + len(start):url.rfind(end)])
        except:
            return False

    def _redeem_oob(self, oobCode: str, email: str) -> Union[str, dict]:

        url = f"{self.baseURL}/identitytoolkit/v3/relyingparty/emailLinkSignin"

        payload = {
            "email": f"{email}",
            "oobCode": f"{oobCode}"
        }

        response = requests.post(url, json=payload, headers=self.headers, params=self.querystring)
        responseJsoned = response.json()

        if response.status_code == 200 and responseJsoned['kind'] == 'identitytoolkit#EmailLinkSigninResponse':
            return {
                'idToken': responseJsoned['idToken'],
                'refreshToken': responseJsoned['refreshToken'],
                'expiresIn': responseJsoned['expiresIn'],
                'localId': responseJsoned['localId'],
            }
        return f"{response.status_code} | Failed to redeem Oob | {response.text}"

    def _refreshTokens(self, refreshToken: str) -> Union[str, dict]:
        url = "https://securetoken.googleapis.com/v1/token"

        payload = {
            "grantType": "refresh_token",
            "refreshToken": f"{refreshToken}"
        }

        response = requests.post(url, json=payload, headers=self.headers, params=self.querystring)
        responseJsoned = response.json()

        if response.status_code == 200:
            return {
                'access_token': responseJsoned['access_token'],
                'expires_in': responseJsoned['expires_in'],
                'refresh_token': responseJsoned['refresh_token'],
                'user_id': responseJsoned['user_id'],
                'project_id': responseJsoned['project_id']
            }
        return f"{response.status_code} | Failed to refresh tokens | {response.text}"


if __name__ == '__main__':
    MailAuth().generate_firebase_token()
