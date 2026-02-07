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


class FlushingRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler that flushes after every write for real-time logs."""
    def emit(self, record):
        super().emit(record)
        self.flush()


class Logger:
    LOGS_DIR = '/mmc/root/loot/bjorn/logs'

    def __init__(self, name, level=logging.INFO, enable_file_logging=True, enable_console_logging=None):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        # Prevent propagation to root logger (avoids duplicate logs)
        self.logger.propagate = False

        # Avoid adding duplicate handlers
        if self.logger.handlers:
            return

        # If console logging not specified, enable only if file logging is disabled
        # This prevents duplicate output when both file and console log the same messages
        if enable_console_logging is None:
            enable_console_logging = not enable_file_logging

        # Create filter (used by both console and file handlers)
        vertical_filter = VerticalFilter()

        if enable_console_logging:
            # Create console handler with standard formatting (includes milliseconds)
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_formatter = logging.Formatter(
                '%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(console_formatter)
            console_handler.addFilter(vertical_filter)

            # Add console handler to the logger
            self.logger.addHandler(console_handler)

        if enable_file_logging:
            try:
                # Ensure the log folder exists
                os.makedirs(self.LOGS_DIR, exist_ok=True)
                log_file_path = os.path.join(self.LOGS_DIR, f"{name}.log")

                # Create file handler with rotation - flushes immediately for real-time logs
                file_handler = FlushingRotatingFileHandler(
                    log_file_path,
                    maxBytes=5*1024*1024,
                    backupCount=2
                )
                file_handler.setLevel(level)
                file_formatter = logging.Formatter(
                    '%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s',
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

    def lifecycle_start(self, module, ip=None, port=None):
        """
        Log the start of a module's execution lifecycle.

        Args:
            module: Name of the module starting execution
            ip: Optional target IP address
            port: Optional target port
        """
        target = f" on {ip}" if ip else ""
        target += f":{port}" if port else ""
        self.logger.info(f"{module} STARTED{target}")

    def lifecycle_end(self, module, status, duration=None, ip=None):
        """
        Log the end of a module's execution lifecycle.

        Args:
            module: Name of the module ending execution
            status: Final status ('success', 'failed', 'timeout', 'interrupted')
            duration: Optional execution duration in seconds
            ip: Optional target IP address
        """
        target = f" for {ip}" if ip else ""
        timing = f" in {duration:.1f}s" if duration is not None else ""
        self.logger.info(f"{module} ENDED ({status}){target}{timing}")

    def lifecycle_timeout(self, module, operation, timeout, ip=None):
        """
        Log a timeout event during module execution.

        Args:
            module: Name of the module experiencing timeout
            operation: Description of the operation that timed out
            timeout: The timeout value in seconds
            ip: Optional target IP address
        """
        target = f" for {ip}" if ip else ""
        self.logger.warning(f"{module} TIMEOUT: {operation} exceeded {timeout}s{target}")


# Example usage
if __name__ == "__main__":
    log = Logger(name="MyLogger", level=logging.INFO, enable_file_logging=False)

    log.debug("This is a debug message")
    log.info("This is an info message")
    log.warning("This is a warning message")
    log.error("This is an error message")
    log.critical("This is a critical message")
    log.success("This is a success message")
