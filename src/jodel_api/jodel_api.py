# -*- coding: utf-8 -*-

from __future__ import (absolute_import, print_function, unicode_literals)
from builtins import input
from future.standard_library import install_aliases

install_aliases()

import base64
import datetime
from hashlib import sha1
import hmac
import json
import random
import requests
from urllib.parse import urlparse
from jodel_api import gcmhack
import time
import collections

s = requests.Session()


class JodelAccount:
    post_colors = ['9EC41C', 'FF9908', 'DD5F5F', '8ABDB0', '06A3CB', 'FFBA00']

    api_url = "https://api.go-tellm.com/api{}"
    client_id = '81e8a76e-1e02-4d17-9ba0-8a7020261b26'
    secret = 'SzsuLtrabXwYuAqZoAmvFypvZdZrYydEOCqoORiy'.encode('ascii')
    version = '5.77.0'

    access_token = None
    device_uid = None

    def __init__(self, lat, lng, city, pushtoken=None, _secret=secret, _version=version, country=None, name=None,
                 update_location=True,
                 access_token=None, device_uid=None, refresh_token=None, distinct_id=None, expiration_date=None,
                 is_legacy=True, **kwargs):
        self.lat, self.lng, self.location_dict = lat, lng, self._get_location_dict(lat, lng, city, country, name)

        self.version = _version

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
            r = self.refresh_all_tokens(pushtoken, **kwargs)
            if r[0] != 200:
                raise Exception("Error creating new account: " + str(r))

    def _send_request(self, method, endpoint, params=None, payload=None, **kwargs):
        url = self.api_url.format(endpoint)
        headers = {'User-Agent': 'Jodel/{} Dalvik/2.1.0 (Linux; U; Android 8.0.0; )'.format(self.version)}
        if self.access_token:
            headers['Authorization'] = 'Bearer ' + self.access_token
        if 'v2/users' not in endpoint:
            headers['X-Location'] = '{0:.4f};{1:.4f}'.format(self.lat, self.lng)

        if 'upvote' in endpoint and params is None:
            params = dict()
            params['home'] = False

        if payload is None:
            payload = {}

        for _ in range(3):
            self._sign_request(method, url, headers, params, payload)
            headers['Content-Type'] = 'application/json; charset=UTF-8'
            headers['Accept-Encoding'] = 'gzip, deflate'
            # print('Requesting {}'.format(url, payload))
            # print('     Endpoint: {}'.format(endpoint))
            # print('     Payload: {}'.format(payload))
            # print('     Method: {}'.format(method))
            # print('     Headers: {}'.format(headers))
            # print('     Parameters: {}'.format(params))
            burp = {'http': '127.0.0.1:8080',
                    'https': '127.0.0.1:8080'}
            resp = s.request(method=method, url=url, params=params, json=payload, headers=headers,
                             # proxies= burp, verify=False,
                             **kwargs)
            if resp.status_code != 502:  # Retry on error 502 "Bad Gateway"
                break

        try:
            resp_text = resp.json(encoding="utf-8")
        except:
            resp_text = resp.text

        return resp.status_code, resp_text

    def _sign_request(self, method, url, headers, params=None, payload=None):
        timestamp = datetime.datetime.utcnow().isoformat()[:-7] + "Z"

        req = [method,
               urlparse(url).netloc,
               "443",
               urlparse(url).path,
               self.access_token if self.access_token else "%"]
        if 'v2/users' not in url:
            req.append('{0:.4f};{1:.4f}'.format(self.lat, self.lng))
        req.append(timestamp),
        req.append("%".join(sorted("{}%{}".format(key, value) for key, value in (params if params else {}).items()))),
        req.append(json.dumps(payload) if payload else '{}')

        secret, version = self.secret, self.version

        # hmac_input = "%".join(req)
        # print('HMAC Input: {}', hmac_input.encode("utf-8"))
        # print('HMAC Secret: {}', secret)
        signature = hmac.new(secret, "%".join(req).encode("utf-8"), sha1).hexdigest().upper()
        # print('HMAC Signature: {}'.format(signature))
        headers['X-Client-Type'] = 'android_{}'.format(version)
        headers['X-Api-Version'] = '0.2'
        headers['X-Timestamp'] = timestamp
        headers['X-Authorization'] = 'HMAC ' + signature

    @staticmethod
    def _get_location_dict(lat, lng, city, country=None, name=None):
        return {"country": country if country else "DE",
                "city": city,
                "loc_coordinates": {"lat": lat, "lng": lng},
                "loc_accuracy": 15.457}

    def get_account_data(self):
        return {'expiration_date': self.expiration_date, 'distinct_id': self.distinct_id,
                'refresh_token': self.refresh_token, 'device_uid': self.device_uid, 'access_token': self.access_token,
                'is_legacy': self.is_legacy}

    def refresh_all_tokens(self, pushToken, **kwargs):
        if pushToken is None:
            pushToken = 'Lulululululu'
        """ Creates a new account with random ID if self.device_uid is not set. Otherwise renews all tokens of the
        account with ID = self.device_uid. """
        if not self.device_uid:
            print("Creating new account.")
            self.is_legacy = False
            self.device_uid = ''.join(random.choice('abcdef0123456789') for _ in range(64))

        payload = {"location": self.location_dict,
                   "iid": pushToken,
                   "client_id": self.client_id,
                   "registration_data": {
                       "channel": "",
                       "referrer_id": "",
                       "campaign": "",
                       "feature": "",
                       "provider": "branch.io",
                       "referrer_branch_id": ""
                   },
                   "device_uid": self.device_uid,
                   "language": "de-DE"}

        print('Creating account with data {}'.format(payload))

        resp = self._send_request("POST", "/v2/users/", payload=payload, **kwargs)
        if resp[0] == 200:
            self.access_token = resp[1]['access_token']
            self.expiration_date = resp[1]['expiration_date']
            self.refresh_token = resp[1]['refresh_token']
            self.distinct_id = resp[1]['distinct_id']
        else:
            raise Exception(resp)
        return resp

    def refresh_access_token(self, **kwargs):
        payload = {"client_id": self.client_id,
                   "distinct_id": self.distinct_id,
                   "refresh_token": self.refresh_token}

        resp = self._send_request("POST", "/v2/users/refreshToken", payload=payload, **kwargs)
        if resp[0] == 200:
            self.access_token = resp[1]['access_token']
            self.expiration_date = resp[1]['expiration_date']
        return resp

    def send_push_token(self, push_token, **kwargs):
        payload = {"client_id": self.client_id, "push_token": push_token}
        return self._send_request("PUT", "/v2/users/pushToken", payload=payload, **kwargs)

    def verify_push(self, server_time, verification_code, **kwargs):
        payload = {"server_time": server_time, "verification_code": verification_code}
        return self._send_request("POST", "/v3/user/verification/push", payload=payload, **kwargs)

    def verify(self, android_account=None, **kwargs):
        if not android_account:
            android_account = gcmhack.AndroidAccount(**kwargs)
            time.sleep(5)

        token = android_account.get_push_token(**kwargs)

        for i in range(3):
            r = self.send_push_token(token, **kwargs)
            if r[0] != 204:
                return r

            try:
                verification = self._read_verificiation(android_account)

                status, r = self.verify_push(verification['server_time'], verification['verification_code'], **kwargs)
                if status == 200 or i == 2:
                    return status, r
            except gcmhack.GcmException:
                if i == 2:
                    raise

    def _read_verificiation(self, android_account):
        for j in range(3):
            try:
                return android_account.receive_verification_from_gcm()
            except gcmhack.GcmException:
                if j == 2:
                    raise

    # ################# #
    # GET POSTS METHODS #
    # ################# #

    def _get_posts(self, post_types="", skip=0, limit=60, after=None, mine=False, hashtag=None, channel=None,
                   pictures=False, lat=None, lng=None, timeRange=None,
                   distance='dynamic', feed_token=None, page=0, home=False, skipHometown=False, **kwargs):

        category = "mine" if mine else "hashtag" if hashtag else "channel" if channel else "location"

        url_params = {"api_version": "v2" if not (hashtag or channel or pictures) else "v3",
                      "pictures_posts": "pictures" if pictures else "posts",
                      "category": category,
                      "post_types": post_types}
        params = {
            "channels": True,
            "after": after,
            "skipHometown": skipHometown,
            "distance": distance,
            "feed_token": feed_token,
            "page": page,
            "lat": lat,
            "home": home,
            "lng": lng
        }

        if timeRange:
            params["timeRange"] = timeRange

        url = "/{api_version}/{pictures_posts}/{category}/{post_types}".format(**url_params)
        return self._send_request("GET", url, params=params, **kwargs)

    def get_posts_recent(self, skip=0, limit=60, after=None, mine=False, hashtag=None, channel=None, **kwargs):
        return self._get_posts('', skip, limit, after, mine, hashtag, channel, **kwargs)

    '''channels = true &
    after = 5
    cd99400613db6001cba9861 &
    skipHometown = false &
    distance = dynamic &
    feed_token = &
    page = 0 &
    lat = 49.88315200805664 &
    home = false &
    lng = 8.669074058532715'''

    def get_posts_popular(self, skip=0, limit=60, after=None, mine=False, hashtag=None, channel=None, timeRange=None,
                          lat=None, lng=None, **kwargs):
        return self._get_posts('popular', skip=skip, limit=limit, after=after, mine=mine, hashtag=hashtag,
                               channel=channel, timeRange=timeRange, lat=lat, lng=lng, **kwargs)

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
        params = {"skip": skip, "limit": limit}
        payload = {"message": message}
        return self._send_request("POST", "/v3/posts/search", params=params, payload=payload, **kwargs)

    # ################### #
    # SINGLE POST METHODS #
    # ################### #

    def create_post(self, message=None, imgpath=None, b64img=None, color=None, ancestor=None, channel="", **kwargs):
        if not imgpath and not message and not b64img:
            raise ValueError("One of message or imgpath must not be null.")

        payload = {"color": color if color else random.choice(self.post_colors),
                   "location": self.location_dict,
                   "ancestor": ancestor,
                   "message": message,
                   "channel": channel}
        if imgpath:
            with open(imgpath, "rb") as f:
                imgdata = base64.b64encode(f.read()).decode("utf-8")
                payload["image"] = imgdata
        elif b64img:
            payload["image"] = b64img

        return self._send_request("POST", '/v3/posts/', payload=payload, **kwargs)

    def get_post_details(self, post_id, **kwargs):
        return self._send_request("GET", '/v2/posts/{}/'.format(post_id), **kwargs)

    def get_post_details_v3(self, post_id, skip=0, **kwargs):
        return self._send_request("GET", '/v3/posts/{}/details'.format(post_id),
                                  params={'details': 'true', 'reply': skip}, **kwargs)

    def upvote(self, post_id, **kwargs):
        return self._send_request("PUT", '/v2/posts/{}/upvote'.format(post_id), **kwargs)

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
        self.lat, self.lng, self.location_dict = lat, lng, self._get_location_dict(lat, lng, city, country, name)
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


# helper function to mock input
def obtain_input(text):
    return input(text)
