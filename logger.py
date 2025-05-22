import logging
from logging.handlers import RotatingFileHandler

def setup_logger(log_file='app.log', log_level=logging.INFO):
    logger = logging.getLogger('application_logger')
    logger.setLevel(log_level)

    # Create a file handler for rotating logs
    handler = RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=5
    )
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)

    # Add the handler to the logger
    if not logger.hasHandlers():
        logger.addHandler(handler)

    return logger
