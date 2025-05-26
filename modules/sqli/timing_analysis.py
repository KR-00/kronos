"""

This script provides functions to measure response times 

I will probably delete it later since the structure changed

it requires changing some of the code since its called on the scanner for the time elapsed 


"""

import time

def measure_response_time(action_callable, *args, **kwargs):
    """
    Measures the execution time of a given action.
    Returns a tuple (result, elapsed_time) where 'result' is the action's output.
    """
    start_time = time.time()
    result = action_callable(*args, **kwargs)
    end_time = time.time()
    elapsed = end_time - start_time
    return result, elapsed

def detect_time_delay(baseline_time, test_time, delay_threshold=0.5):
    """
    Compares the baseline response time with the test response time to detect
    significant delays that may indicate a time-based SQL injection.
    Returns True if (test_time - baseline_time) > delay_threshold.
    """
    return (test_time - baseline_time) > delay_threshold
