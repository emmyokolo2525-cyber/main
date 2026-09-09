import json
from unittest import mock
import urllib.error

from webhook import sign_payload, dispatch_webhook

def test_sign_payload():
    payload = b'{"hello": "world"}'
    secret = "mysecret"
    timestamp = 1620000000
    sig = sign_payload(payload, secret, timestamp)
    assert len(sig) == 64  # SHA-256 hex digest length
    
    sig2 = sign_payload(payload, secret, timestamp)
    assert sig == sig2

@mock.patch("webhook.urllib.request.urlopen")
@mock.patch("webhook.update_delivery_status")
def test_dispatch_webhook_success(mock_update, mock_urlopen):
    mock_response = mock.MagicMock()
    mock_response.getcode.return_value = 200
    mock_urlopen.return_value.__enter__.return_value = mock_response

    delivery = {
        "delivery_id": 1,
        "url": "http://example.com/webhook",
        "secret_key": "sec",
        "retry_count": 0,
        "payload": {"event_type": "embed"}
    }
    dispatch_webhook(delivery)
    
    mock_update.assert_called_once_with(1, True, 200, 0)
    
@mock.patch("webhook.urllib.request.urlopen")
@mock.patch("webhook.update_delivery_status")
def test_dispatch_webhook_failure(mock_update, mock_urlopen):
    mock_urlopen.side_effect = urllib.error.HTTPError("http://example.com", 500, "Internal Error", {}, None)

    delivery = {
        "delivery_id": 2,
        "url": "http://example.com/webhook",
        "secret_key": "sec",
        "retry_count": 1,
        "payload": {"event_type": "extract"}
    }
    dispatch_webhook(delivery)
    
    mock_update.assert_called_once_with(2, False, 500, 1)
