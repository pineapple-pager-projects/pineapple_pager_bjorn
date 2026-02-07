# timeout_utils.py
# Description:
# Shared timeout utilities for graceful shutdown handling across all attack modules.
# Provides reusable patterns for subprocess management, thread joining, and queue draining.

import subprocess
import threading
import time
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from functools import wraps


def run_with_timeout(func, timeout, *args, **kwargs):
    """
    Run a function with a timeout wrapper using ThreadPoolExecutor.

    Args:
        func: The function to execute
        timeout: Maximum time in seconds to wait for completion
        *args: Positional arguments to pass to the function
        **kwargs: Keyword arguments to pass to the function

    Returns:
        The function's return value, or raises TimeoutError if it exceeds timeout

    Raises:
        TimeoutError: If the function execution exceeds the specified timeout
        Exception: Any exception raised by the function itself
    """
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except FuturesTimeoutError:
            raise TimeoutError(f"Function {func.__name__} timed out after {timeout} seconds")


def subprocess_with_timeout(cmd, timeout=60, shell=True):
    """
    Run a subprocess with guaranteed termination on timeout.

    Args:
        cmd: Command to execute (string if shell=True, list if shell=False)
        timeout: Maximum time in seconds to wait for completion
        shell: Whether to run through shell (default True)

    Returns:
        tuple: (stdout, stderr, returncode)

    Raises:
        subprocess.TimeoutExpired: If process exceeds timeout (after cleanup)
    """
    process = subprocess.Popen(
        cmd,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return stdout, stderr, process.returncode
    except subprocess.TimeoutExpired:
        # Kill the process
        process.kill()
        # Wait for it to actually terminate (with a short timeout)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Force terminate if kill didn't work
            process.terminate()
            process.wait(timeout=2)
        raise


def drain_queue_safely(queue, timeout=1.0):
    """
    Safely drain a queue to prevent queue.join() from blocking indefinitely.

    This function removes all items from the queue and marks them as done,
    ensuring that any waiting join() calls can proceed.

    Args:
        queue: The Queue instance to drain
        timeout: Time to wait for each get operation (default 1.0)

    Returns:
        int: Number of items drained from the queue
    """
    drained = 0
    while True:
        try:
            queue.get(timeout=timeout)
            queue.task_done()
            drained += 1
        except Empty:
            break
    return drained


def join_threads_with_timeout(threads, timeout=10, logger=None):
    """
    Join multiple threads with individual timeouts.

    Args:
        threads: List of threading.Thread objects to join
        timeout: Maximum time in seconds to wait for each thread
        logger: Optional logger to report hanging threads

    Returns:
        list: List of threads that did not terminate within the timeout
    """
    hanging_threads = []
    for t in threads:
        t.join(timeout=timeout)
        if t.is_alive():
            hanging_threads.append(t)
            if logger:
                logger.warning(f"Thread {t.name} did not terminate within {timeout}s timeout")
    return hanging_threads


def wait_for_queue_with_timeout(queue, timeout=60, check_interval=1.0, should_exit_func=None):
    """
    Wait for a queue to be empty with timeout and exit signal checking.

    Args:
        queue: The Queue instance to wait on
        timeout: Maximum total time to wait in seconds
        check_interval: How often to check for exit signal
        should_exit_func: Optional callable that returns True if we should exit early

    Returns:
        bool: True if queue emptied normally, False if timeout or exit signal
    """
    start_time = time.time()
    while not queue.empty():
        if should_exit_func and should_exit_func():
            # Drain remaining items
            drain_queue_safely(queue)
            return False
        if time.time() - start_time > timeout:
            # Drain remaining items
            drain_queue_safely(queue)
            return False
        time.sleep(check_interval)
    return True


class GracefulWorker:
    """
    Base class for worker threads that need graceful shutdown support.

    Usage:
        class MyWorker(GracefulWorker):
            def process_item(self, item):
                # Do work with item
                pass

        worker = MyWorker(queue, shared_data)
        worker.run()
    """

    def __init__(self, queue, shared_data, logger=None):
        self.queue = queue
        self.shared_data = shared_data
        self.logger = logger

    def should_exit(self):
        """Check if the orchestrator has signaled exit."""
        return getattr(self.shared_data, 'orchestrator_should_exit', False)

    def process_item(self, item):
        """Override this method to process queue items."""
        raise NotImplementedError("Subclasses must implement process_item()")

    def run(self):
        """Main worker loop with graceful shutdown support."""
        while True:
            if self.should_exit():
                if self.logger:
                    self.logger.info("Exit signal received, worker stopping")
                break
            try:
                item = self.queue.get(timeout=1.0)
            except Empty:
                if self.queue.empty():
                    break
                continue
            try:
                self.process_item(item)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error processing item: {e}")
            finally:
                self.queue.task_done()


class TimeoutContext:
    """
    Context manager for operations that need a timeout with cleanup.

    Usage:
        with TimeoutContext(timeout=60, on_timeout=cleanup_func) as ctx:
            # Do long-running operation
            if ctx.should_stop:
                break
    """

    def __init__(self, timeout, on_timeout=None, check_interval=1.0):
        self.timeout = timeout
        self.on_timeout = on_timeout
        self.check_interval = check_interval
        self.start_time = None
        self.should_stop = False
        self._timer = None

    def __enter__(self):
        self.start_time = time.time()
        self._timer = threading.Timer(self.timeout, self._handle_timeout)
        self._timer.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._timer:
            self._timer.cancel()
        return False

    def _handle_timeout(self):
        self.should_stop = True
        if self.on_timeout:
            self.on_timeout()

    def elapsed(self):
        """Return elapsed time since context started."""
        if self.start_time:
            return time.time() - self.start_time
        return 0

    def remaining(self):
        """Return remaining time before timeout."""
        return max(0, self.timeout - self.elapsed())


def with_connection_timeout(connect_func, timeout=30):
    """
    Decorator/wrapper for connection functions that need timeouts.

    Args:
        connect_func: The connection function to wrap
        timeout: Maximum time to wait for connection

    Returns:
        Wrapped function that enforces timeout
    """
    @wraps(connect_func)
    def wrapper(*args, **kwargs):
        return run_with_timeout(connect_func, timeout, *args, **kwargs)
    return wrapper
