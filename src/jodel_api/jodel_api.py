# -*- coding: utf-8 -*-

from __future__ import (absolute_import, print_function, unicode_literals)

from builtins import input

from future.standard_library import install_aliases

from jodel_api.android_auth import MailAuth

install_aliases()

import base64
import datetime
from hashlib import sha1
import hmac
import json
import random
import requests
from urllib.parse import urlparse

s = requests.Session()


class JodelAccount:
    post_colors = ['9EC41C', 'FF9908', 'DD5F5F', '8ABDB0', '06A3CB', 'FFBA00']

    api_url = "https://api.jodelapis.com/api{}"
    client_id = 'cd871f92-a23f-4afc-8fff-51ff9dc9184e'
    firebase_uid = 'jtNECbcwmfPGgQVuyKVPpsW8UIE3'
    secret = 'YEKawcOEwzigovvWEFkBVWPIsgHhnIFmfMtfjYLS'.encode('ascii')
    version = '7.51'
    client_type = 'ios_{}'

    access_token = None
    device_uid = None

    debug = False

    def __init__(self, lat, lng, city, _secret=None, _version=None, _client_id=None, country=None, name=None,
                 update_location=True,
                 access_token=None, device_uid=None, refresh_token=None, distinct_id=None, expiration_date=None,
                 is_legacy=True, _debug=False, email_fetch=None, email_address=None, _client_type=None, **kwargs):
        self.lat, self.lng, self.location_dict = lat, lng, self._get_location_dict(lat, lng, city, country)

        self.email_address = email_address
        self.email_fetch = email_fetch

        if _secret:
            self.secret = _secret

        if _version:
            self.version = _version

        if _client_id:
            self.client_id = _client_id

        if _client_type:
            self.client_type = _client_type

        self.version = _version

        self.debug = _debug

        self.is_legacy = is_legacy
        if device_uid:
            self.device_uid = device_uid

        if access_token and device_uid and refresh_token and distinct_id and expiration_date:
            self.expiration_date = expiration_date
            self.distinct_id = distinct_id
            self.refresh_token = refresh_token
            self.access_token = access_token
            if update_location:
                r = self.set_location(lat, lng, city, country, name, **kwargs)
                if r[0] != 204:
                    raise Exception("Error updating location: " + str(r))

        else:
            status, response = self.refresh_all_tokens(**kwargs)
            if status != 200:
                raise Exception("Error creating new account: " + str(response))

    def _send_request(self, method, endpoint, params=None, payload=None, **kwargs):
        url = self.api_url.format(endpoint)
        headers = {'User-Agent': 'python-requests / jodel_api {} (https://github.com/JodelRaccoons/jodel_api/)'.format(self.version)}
        if self.access_token:
            headers['Authorization'] = 'Bearer ' + self.access_token
        if 'v2/users' not in endpoint:
            headers['X-Location'] = '{0:.6f};{1:.6f}'.format(self.lat, self.lng)

        if payload is None:
            payload = {}

        for _ in range(3):
            self._sign_request(method, url, headers, params, payload)
            headers['Content-Type'] = 'application/json; charset=UTF-8'
            headers['Accept-Encoding'] = 'gzip, deflate'
            headers['X-Location-Type'] = 'local'
            if self.debug:
                print('Requesting {}'.format(url, payload))
                print('     Endpoint: {}'.format(endpoint))
                print('     Payload: {}'.format(payload))
                print('     Method: {}'.format(method))
                print('     Headers: {}'.format(headers))
                print('     Parameters: {}'.format(params))
            proxies = {
                'http': 'http://127.0.0.1:8081',
                'https': 'http://127.0.0.1:8081'
            }
            resp = s.request(method=method, url=url, params=params, json=payload, headers=headers,
                             #proxies=proxies,
                             #verify=False,
                             **kwargs)
            if resp.status_code != 502:  # Retry on error 502 "Bad Gateway"
                break

        try:
            if resp.status_code == 204:
                return resp.status_code,

            if resp.text:
                resp_text = resp.json()
                if self.debug:
                    print('Response: ' + resp_text)
        except:
            if self.debug:
                print('Response: ' + resp.text)
            resp_text = json.loads(resp.text)

        return resp.status_code, resp_text

    def _sign_request(self, method, url, headers, params=None, payload=None):
        timestamp = datetime.datetime.utcnow().isoformat()[:-7] + "Z"

        req = [method,
               urlparse(url).netloc,
               "443",
               urlparse(url).path,
               self.access_token if self.access_token else "%"]
        if 'v2/users' not in url:
            req.append('{0:.6f};{1:.6f}'.format(self.lat, self.lng))
        req.append(timestamp),
        req.append("%".join(sorted("{}%{}".format(key, value) for key, value in (params if params else {}).items()))),
        req.append(json.dumps(payload) if payload else '{}')

        secret, version = self.secret, self.version

        hmac_input = "%".join(req).encode("utf-8").strip()
        if self.debug:
            print("HMAC Input", hmac_input)
            print("HMAC Key", self.secret, "version", self.version)
        signature = hmac.new(secret, hmac_input, sha1).hexdigest().upper()
        headers['X-Client-Type'] = self.client_type.format(version)
        headers['X-Api-Version'] = '0.2'
        headers['X-Timestamp'] = timestamp
        headers['X-Authorization'] = 'HMAC ' + signature

    @staticmethod
    def _get_location_dict(lat, lng, city, country=None):
        return {"country": country if country else "DE",
                "city": city,
                "loc_coordinates": {"lat": lat, "lng": lng},
                "loc_accuracy": 15.457}

    def get_account_data(self):
        return {'expiration_date': self.expiration_date, 'distinct_id': self.distinct_id,
                'refresh_token': self.refresh_token, 'device_uid': self.device_uid, 'access_token': self.access_token,
                'is_legacy': self.is_legacy}

    def refresh_all_tokens(self, **kwargs):
        """ Creates a new account with random ID if self.device_uid is not set. Otherwise renews all tokens of the
        account with ID = self.device_uid. """
        if not self.device_uid:
            print("Creating new account.")
            self.is_legacy = False
            self.device_uid = ''.join(random.choice('abcdef0123456789') for _ in range(64))

        payload = {"location": self.location_dict,
                   "device_uid": self.device_uid,
                   "language": "de-DE",
                   "client_id": self.client_id}

        print('Creating account with data {}'.format(payload))

        status_code, response = self._send_request("POST", "/v2/users", payload=payload, **kwargs)
        if self.debug:
            print('Refresh all tokens response: ', response)
        if status_code == 200:
            self.access_token = response['access_token']
            self.expiration_date = response['expiration_date']
            self.refresh_token = response['refresh_token']
            self.distinct_id = response['distinct_id']
        else:
            raise Exception(response)
        return status_code, response

    def refresh_access_token(self, **kwargs):
        payload = {"client_id": self.client_id,
                   "distinct_id": self.distinct_id,
                   "refresh_token": self.refresh_token}

        status_code, response = self._send_request("POST", "/v2/users/refreshToken", payload=payload, **kwargs)
        if status_code == 200:
            self.access_token = response['access_token']
            self.expiration_date = response['expiration_date']
        return status_code, response

    def send_push_token(self, push_token, **kwargs):
        payload = {"client_id": self.client_id, "push_token": push_token}
        return self._send_request("PUT", "/v2/users/pushToken", payload=payload, **kwargs)

    # ################# #
    # GET POSTS METHODS #
    # ################# #

    def _get_posts(self, post_types="", skip=0, limit=60, after=None, mine=False, hashtag=None, channel=None,
                   pictures=False, lat=None, lng=None, time_range=None,
                   distance='dynamic', feed_token=None, page=0, home=False, skip_hometown=False, **kwargs):

        category = "mine" if mine else "hashtag" if hashtag else "channel" if channel else "location"

        url_params = {"api_version": "v2" if not (hashtag or channel or pictures) else "v3",
                      "pictures_posts": "pictures" if pictures else "posts",
                      "category": category,
                      "post_types": post_types}
        params = {
            "channels": True,
            "after": after,
            "skipHometown": skip_hometown,
            "distance": distance,
            "feed_token": feed_token,
            "page": page,
            "lat": lat,
            "home": home,
            "hashtag": hashtag,
            "channel": channel,
            "skip": skip,
            "limit": limit,
            "lng": lng
        }

        if time_range:
            params["timeRange"] = time_range

        url = "/{api_version}/{pictures_posts}/{category}/{post_types}".format(**url_params)
        return self._send_request("GET", url, params=params, **kwargs)

    def get_posts_recent(self, skip=0, limit=60, after=None, mine=False, hashtag=None, channel=None, **kwargs):
        return self._get_posts('', skip, limit, after, mine, hashtag, channel, **kwargs)

    def get_posts_popular(self, skip=0, limit=60, after=None, mine=False, hashtag=None, channel=None, time_range=None,
                          lat=None, lng=None, **kwargs):
        return self._get_posts('popular', skip=skip, limit=limit, after=after, mine=mine, hashtag=hashtag,
                               channel=channel, time_range=time_range, lat=lat, lng=lng, **kwargs)

    def get_posts_discussed(self, skip=0, limit=60, after=None, mine=False, hashtag=None, channel=None, **kwargs):
        return self._get_posts('discussed', skip, limit, after, mine, hashtag, channel, **kwargs)

    def get_pictures_recent(self, skip=0, limit=60, after=None, **kwargs):
        return self._get_posts('', skip, limit, after, pictures=True, **kwargs)

    def get_pictures_popular(self, skip=0, limit=60, after=None, **kwargs):
        return self._get_posts('popular', skip, limit, after, pictures=True, **kwargs)

    def get_pictures_discussed(self, skip=0, limit=60, after=None, **kwargs):
        return self._get_posts('discussed', skip, limit, after, pictures=True, **kwargs)

    def get_my_pinned_posts(self, skip=0, limit=60, after=None, **kwargs):
        return self._get_posts('pinned', skip, limit, after, True, **kwargs)

    def get_my_replied_posts(self, skip=0, limit=60, after=None, **kwargs):
        return self._get_posts('replies', skip, limit, after, True, **kwargs)

    def get_my_voted_posts(self, skip=0, limit=60, after=None, **kwargs):
        return self._get_posts('votes', skip, limit, after, True, **kwargs)

    def post_search(self, message, skip=0, limit=60, **kwargs):
        params = {"message": message, "skip": skip, "limit": limit }
        return self._send_request("GET", "/v3/posts/textSearch?", params=params, **kwargs)

    # ################### #
    # SINGLE POST METHODS #
    # ################### #

    def create_post(self, message=None, imgpath=None, b64img=None, color=None, ancestor=None, channel=None, **kwargs):
        if not imgpath and not message and not b64img:
            raise ValueError("One of message or imgpath must not be null.")

        payload = {"color": color if color else random.choice(self.post_colors),
                   "location": self.location_dict,
                   "ancestor": ancestor,
                   "message": message,
                   "channel_id": channel if channel else '5f8ebbb3fd37e500256f7a67'}
        if imgpath:
            with open(imgpath, "rb") as f:
                imgdata = base64.b64encode(f.read()).decode("utf-8")
                payload["image"] = imgdata
        elif b64img:
            payload["image"] = b64img

        return self._send_request("POST", '/v3/posts/', payload=payload, **kwargs)

    # endpoint in api version v2 is disabled
    def get_post_details(self, post_id, **kwargs):
        return self.get_post_details_v3(post_id, **kwargs)

    def get_post_details_v3(self, post_id, skip=0, **kwargs):
        return self._send_request("GET", '/v3/posts/{}/details'.format(post_id),
                                  params={'details': True, 'reply': skip}, **kwargs)

    def upvote(self, post_id, home=False, explorer=False, isRecommended=False, section='Main', sorting='newest', filter='Now', **kwargs):
        params = {'home': home, 'explorer': explorer, 'isRecommended':isRecommended, 'section': section, 'sorting':sorting, 'filter':filter}
        return self._send_request("PUT", '/v2/posts/{}/upvote'.format(post_id), params=params, **kwargs)

    def downvote(self, post_id, **kwargs):
        return self._send_request("PUT", '/v2/posts/{}/downvote/'.format(post_id), **kwargs)

    def give_thanks(self, post_id, **kwargs):
        return self._send_request("POST", '/v3/posts/{}/giveThanks'.format(post_id), **kwargs)

    def get_share_url(self, post_id, **kwargs):
        return self._send_request("POST", "/v3/posts/{}/share".format(post_id), **kwargs)

    def pin(self, post_id, **kwargs):
        return self._send_request("PUT", "/v2/posts/{}/pin".format(post_id), **kwargs)

    def unpin(self, post_id, **kwargs):
        return self._send_request("PUT", "/v2/posts/{}/unpin".format(post_id), **kwargs)

    def enable_notifications(self, post_id, **kwargs):
        return self._send_request("PUT", "/v2/posts/{}/notifications/enable".format(post_id), **kwargs)

    def disable_notifications(self, post_id, **kwargs):
        return self._send_request("PUT", "/v2/posts/{}/notifications/disable".format(post_id), **kwargs)

    def delete_post(self, post_id, **kwargs):
        return self._send_request("DELETE", "/v2/posts/{}".format(post_id), **kwargs)

    # ################### #
    # STICKY POST METHODS #
    # ################### #

    def upvote_sticky_post(self, post_id, **kwargs):
        return self._send_request("PUT", "/v3/stickyposts/{}/up".format(post_id), **kwargs)

    def downvote_sticky_post(self, post_id, **kwargs):
        return self._send_request("PUT", "/v3/stickyposts/{}/down".format(post_id), **kwargs)

    def dismiss_sticky_post(self, post_id, **kwargs):
        return self._send_request("PUT", "/v3/stickyposts/{}/dismiss".format(post_id), **kwargs)

    # #################### #
    # NOTIFICATION METHODS #
    # #################### #

    def get_notifications(self, **kwargs):
        return self._send_request("PUT", "/v3/user/notifications", **kwargs)

    def get_notifications_new(self, **kwargs):
        return self._send_request("GET", "/v3/user/notifications/new", **kwargs)

    def notification_read(self, post_id=None, notification_id=None, **kwargs):
        if post_id:
            return self._send_request("PUT", "/v3/user/notifications/post/{}/read".format(post_id), **kwargs)
        elif notification_id:
            return self._send_request("PUT", "/v3/user/notifications/{}/read".format(notification_id), **kwargs)
        else:
            raise ValueError("One of post_id or notification_id must not be null.")

    # ############### #
    # CHANNEL METHODS #
    # ############### #

    def get_recommended_channels(self, **kwargs):
        return self._send_request("GET", "/v3/user/recommendedChannels", **kwargs)

    def get_channel_meta(self, channel, **kwargs):
        return self._send_request("GET", "/v3/user/channelMeta", params={"channel": channel}, **kwargs)

    def follow_channel(self, channel, **kwargs):
        return self._send_request("PUT", "/v3/user/followChannel", params={"channel": channel}, **kwargs)

    def unfollow_channel(self, channel, **kwargs):
        return self._send_request("PUT", "/v3/user/unfollowChannel", params={"channel": channel}, **kwargs)

    # ############ #
    # USER METHODS #
    # ############ #

    def set_location(self, lat, lng, city, country=None, name=None, **kwargs):
        self.lat, self.lng, self.location_dict = lat, lng, self._get_location_dict(lat, lng, city, country)
        return self._send_request("PUT", "/v2/users/location", payload={"location": self.location_dict}, **kwargs)

    def set_user_profile(self, user_type=None, gender=None, age=None, **kwargs):
        allowed_user_types = ["high_school", "high_school_graduate", "student", "apprentice", "employee", "other", None]
        if user_type and user_type not in allowed_user_types:
            raise ValueError("user_type must be one of {}.".format(allowed_user_types))

        if gender not in ["m", "f", None]:
            raise ValueError("gender must be either m or f.")

        return self._send_request("PUT", "/v3/user/profile",
                                  payload={"user_type": user_type, "gender": gender, "age": age}, **kwargs)

    def get_karma(self, **kwargs):
        return self._send_request("GET", "/v2/users/karma", **kwargs)

    def get_user_config(self, **kwargs):
        return self._send_request("GET", "/v3/user/config", **kwargs)


class iOSJodelAccount(JodelAccount):
    def __init__(self, lat, lng, city, **kwargs):
        secret = 'YEKawcOEwzigovvWEFkBVWPIsgHhnIFmfMtfjYLS'.encode('ascii')
        version = '7.51'
        client_type = 'ios_{}'
        super().__init__(lat, lng, city, _secret=secret, _version=version, _client_type=client_type, **kwargs)


class AndroidJodelAccount(JodelAccount):
    def __init__(self, lat, lng, city, **kwargs):
        secret = 'PohIBVvuWFhSLydTFZSjDMWmHrpRQuEGEBPfgIxB'.encode('ascii')
        version = '8.0.1'
        client_type = 'android_{}'
        super().__init__(lat, lng, city, _secret=secret, _version=version, _client_type=client_type, _client_id='81e8a76e-1e02-4d17-9ba0-8a7020261b26', **kwargs)

    def refresh_all_tokens(self, **kwargs):
        """
        Mimics the Android account creation via email
        Prompts the user for input if email_fetch and email_address are not set within the constructor
        email_address: str -> test@mail.com
        email_fetch: function with email_address as parameter
            -> function should return the content of the email e.g.
            def email_fetcher(email_address):
                email = None
                while not email:
                    response = requests.get(f"https://your.email.service/{email_address}").text
                    if "oobCode" in response:
                        return response
                    else:
                        time.sleep(1)
        """
        if not self.email_address:
            self.email_address = input("No email address is given, please enter it manually: ")
        if not self.email_fetch:
            def email_fetch(email):
                return input("Please enter the link found in the email: ")
            self.email_fetch = email_fetch
        auth = MailAuth(self.email_address, self.email_fetch)
        firebase_token = auth.generate_firebase_token()

        if not self.device_uid:
            print("Creating new account.")
            self.is_legacy = False
            self.device_uid = ''.join(random.choice('abcdef0123456789') for _ in range(64))

        payload = {"firebase_uid": self.firebase_uid,
                   "firebaseJWT": firebase_token,
                   "location": self.location_dict,
                   "device_uid": self.device_uid,
                   "language": "de-DE",
                   "client_id": self.client_id}

        print('Creating account with data {}'.format(payload))

        status_code, response = self._send_request("POST", "/v2/users", payload=payload, **kwargs)
        if self.debug:
            print('Refresh all tokens response: ', response)
        if status_code == 200:
            self.access_token = response['access_token']
            self.expiration_date = response['expiration_date']
            self.refresh_token = response['refresh_token']
            self.distinct_id = response['distinct_id']
        else:
            raise Exception(response)
        return status_code, response


# helper function to mock input
def obtain_input(text):
    return input(text)
