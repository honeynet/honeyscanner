import logging
from error_messages import ERROR_MESSAGES

class ErrorHandler:
    def __init__(self):
        self.logger = logging.getLogger('honeyscanner')
        self._setup_logging()
    
    def _setup_logging(self):
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler = logging.FileHandler('honeyscanner.log')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def handle_error(self, error_type, **kwargs):
        if error_type in ERROR_MESSAGES:
            self.logger.error(ERROR_MESSAGES[error_type]['log'].format(**kwargs))
            return ERROR_MESSAGES[error_type]['user']
        return "An unexpected error occurred. Please check logs for details."
