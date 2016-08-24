# Jodel API

Inofficial interface to the private API of the Jodel App. Not affiliated with *The Jodel Venture GmbH*.

##Usage

```python
>>> import jodel_api
>>> lat, lng, city = 48.148434, 11.567867, "Munich"

>>> # Calling the bare constructor creates a new account
>>> j = jodel_api.JodelAccount(lat=lat, lng=lng, city=city)
Creating new account.

>>> # get_account_data() returns all data associated with this account (censored by me)
>>> j.get_account_data()
{'access_token': 'xxx', 'expiration_date': 1472660000, 'refresh_token': 'xxx', 'distinct_id': 'xxx', 'device_uid': 'xxx'}

>>> # Save this data to reuse the account later on, feed it to the JodelAccount() constructor to reinitiate the account
>>> # This constructor issues one request to update the location of the account
>>> j = jodel_api.JodelAccount(lat=lat, lng=lng, city=city, access_token='xxx', expiration_date='xxx', 
                               refresh_token='xxx', distinct_id='xxx', device_uid='xxx')
(204, '')
>>> # Add update_location=False to suppress this behaviour. The constructor will only instantiate an object, without making any remote calls
>>> j = jodel_api.JodelAccount(lat=lat, lng=lng, city=city, update_location=False, 
                               access_token='xxx', expiration_date='xxx', refresh_token='xxx', 
                               distinct_id='xxx', device_uid='xxx')
```

All remote API calls return a tuple of HTTP status_code and the response (if possible a dict (parsed from the API response), but might also be a string (error message)

```python
>>> # After expiration_date has passed, call refresh_access_tokens() to re-authenticate
>>> j.refresh_access_token()
(200, {'token_type': 'bearer', 'access_token': 'xxx', 'expires_in': 604800, 'expiration_date': xxx})

>>> # If refresh_access_token fails, use refresh_all_tokens instead (this is akin to creating a new account, but preserves the account's data (karma, etc))
>>> j.refresh_all_tokens()
(200, {'expires_in': 604800, 'access_token': 'xxx', 'token_type': 'bearer', 'returning': True, 'refresh_token': 'xxx', 'expiration_date': 1472600000, 'distinct_id': 'xxx'})

>>> # The following API calls are supported (presented without their respective responses)
>>> set_location(lat, lng, city, country=None, name=None) # country and name appear to have no effect
>>> create_post(message=None, imgpath=None, color=None)
>>> get_posts_recent(skip=None, limit=60, mine=False)
>>> get_posts_popular(skip=None, limit=60, mine=False)
>>> get_posts_discussed(skip=None, limit=60, mine=False)
>>> get_post_details(self, post_id)
>>> upvote(post_id)
>>> downvote(post_id)
>>> get_user_config()
>>> get_karma()
>>> delete_post(post_id) # Only works on your own posts ಠ_ಠ
```

## Rate-Limits

The Jodel API appears to have the following (IP-based) rate-limits

- max of 60 new account registrations from one IP per half hour
- max of 200 (?) votes (possibly also post creations?) in an unknown time frame
