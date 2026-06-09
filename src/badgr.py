"""Badgr badge issuance for the ``/secret`` endpoint.

Ported from the Flask ``Secret`` / ``GetAccessToken`` handlers.  The DynamoDB
access-token cache is replaced by Workers KV, and the synchronous ``requests``
calls are replaced by the runtime's async ``fetch``.
"""

import json

from js import fetch
from pyodide.ffi import to_js
from js import Object

BADGR_TOKEN_URL = "https://api.badgr.io/o/token"
BADGR_ISSUER = "oikqaDC8Sx2WPNXUYdh0Dw"
BADGR_ASSERTIONS_URL = "https://api.badgr.io/v2/issuers/%s/assertions" % BADGR_ISSUER

# Access tokens are valid for ~8 hours; refresh anything older.
ACCESS_TOKEN_MAX_AGE = 28800


def _js(obj):
    return to_js(obj, dict_converter=Object.fromEntries)


async def _get_access_token(env):
    """Return a Badgr access token, refreshing + caching via KV as needed."""
    cache = env.BADGR_CACHE
    refresh_token = await cache.get("badger-refresh-token")
    if refresh_token is None:
        refresh_token = str(env.BADGR_REFRESH)

    form = "grant_type=refresh_token&refresh_token=%s" % refresh_token
    resp = await fetch(
        BADGR_TOKEN_URL,
        _js(
            {
                "method": "POST",
                "headers": {"content-type": "application/x-www-form-urlencoded"},
                "body": form,
            }
        ),
    )
    data = json.loads(await resp.text())

    await cache.put("badger-access-token", data["access_token"], _js({"expirationTtl": ACCESS_TOKEN_MAX_AGE}))
    # Refresh tokens are single-use; persist the rotated one.
    await cache.put("badger-refresh-token", data["refresh_token"])
    return data["access_token"]


async def issue_badge(token, env):
    """Issue the demo badge to the token's ``sub`` email.  Returns response text."""
    if "sub" not in token:
        return (
            "Congratulations!  But you didn't include an email in the 'sub' "
            "attribute of the token, therefore we cannot issue you a badge"
        )

    email = token["sub"]
    access_token = await _get_access_token(env)
    badge = {
        "badgeclassOpenBadgeId": "https://api.badgr.io/public/badges/0xFqlz4bQ5qAd7FG6FIwEQ",
        "issuer": BADGR_ISSUER,
        "issuerOpenBadgeId": "https://api.badgr.io/public/issuers/%s" % BADGR_ISSUER,
        "recipient": {"identity": email, "hashed": False, "type": "email", "salt": ""},
        "narrative": "Successfully queried the demo token issuer",
        "evidence": [
            {
                "url": "https://demo.scitokens.org",
                "narrative": "Successfully queried the demo token issuer",
            }
        ],
    }

    resp = await fetch(
        BADGR_ASSERTIONS_URL,
        _js(
            {
                "method": "POST",
                "headers": {
                    "Authorization": "Bearer " + access_token,
                    "content-type": "application/json",
                },
                "body": json.dumps(badge),
            }
        ),
    )
    data = json.loads(await resp.text())
    return (
        "Congratulations, you have earned the Demo Application badge: "
        + data["result"][0]["openBadgeId"]
    )
