from honeyscanner.error_handler import ErrorHandler

def test_invalid_ip():
    error_handler = ErrorHandler()
    message = error_handler.handle_error('invalid_ip', ip='invalid')
    assert 'Invalid IP address' in message

def test_timeout():
    error_handler = ErrorHandler()
    message = error_handler.handle_error('connection_timeout', ip='8.8.8.8', timeout=30)
    assert 'Connection timed out' in message
