#logger.py
# Description:
# Simple logging module for Bjorn on WiFi Pineapple Pager.
# Rewritten to use standard Python logging (no external dependencies).

import logging
from logging.handlers import RotatingFileHandler
import os

# Define custom log level "SUCCESS"
SUCCESS_LEVEL_NUM = 25
logging.addLevelName(SUCCESS_LEVEL_NUM, "SUCCESS")

def success(self, message, *args, **kwargs):
    if self.isEnabledFor(SUCCESS_LEVEL_NUM):
        self._log(SUCCESS_LEVEL_NUM, message, args, **kwargs)

logging.Logger.success = success


class VerticalFilter(logging.Filter):
    def filter(self, record):
        return 'Vertical' not in record.getMessage()


class Logger:
    LOGS_DIR = '/mmc/root/loot/bjorn/logs'

    def __init__(self, name, level=logging.DEBUG, enable_file_logging=True):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Avoid adding duplicate handlers
        if self.logger.handlers:
            return

        # Create console handler with standard formatting
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)

        # Add filter to console handler
        vertical_filter = VerticalFilter()
        console_handler.addFilter(vertical_filter)

        # Add console handler to the logger
        self.logger.addHandler(console_handler)

        if enable_file_logging:
            try:
                # Ensure the log folder exists
                os.makedirs(self.LOGS_DIR, exist_ok=True)
                log_file_path = os.path.join(self.LOGS_DIR, f"{name}.log")

                # Create file handler with rotation
                file_handler = RotatingFileHandler(
                    log_file_path,
                    maxBytes=5*1024*1024,
                    backupCount=2
                )
                file_handler.setLevel(level)
                file_formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                file_handler.setFormatter(file_formatter)

                # Add filter to file handler
                file_handler.addFilter(vertical_filter)

                # Add file handler to the logger
                self.logger.addHandler(file_handler)
            except Exception as e:
                # If file logging fails, just continue with console
                print(f"Warning: Could not set up file logging: {e}")

    def set_level(self, level):
        self.logger.setLevel(level)
        for handler in self.logger.handlers:
            handler.setLevel(level)

    def debug(self, message):
        self.logger.debug(message)

    def info(self, message):
        self.logger.info(message)

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def critical(self, message):
        self.logger.critical(message)

    def success(self, message):
        self.logger.success(message)

    def disable_logging(self):
        logging.disable(logging.CRITICAL)


# Example usage
if __name__ == "__main__":
    log = Logger(name="MyLogger", level=logging.DEBUG, enable_file_logging=False)

    log.debug("This is a debug message")
    log.info("This is an info message")
    log.warning("This is a warning message")
    log.error("This is an error message")
    log.critical("This is a critical message")
    log.success("This is a success message")
