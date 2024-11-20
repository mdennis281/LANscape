
from ..libraries.ip_parser import get_address_count
import webview, time

from concurrent.futures import ThreadPoolExecutor, Future
def right_size_subnet(subnet: str):
    """
    Used to improve speed of test time
    """
    if get_address_count(subnet) > 500:
        parts = subnet.split('/')
        ip = parts[0]
        mask = int(parts[1])
        mask += 1
        return right_size_subnet(f"{ip}/{mask}")
    return subnet

def webview_client(title, url):
    def decorator(func):
        def wrapper(*args, **kwargs):
            baseclass = args[0]

            # Create the WebView window
            window = webview.create_window(title, url)

            # Create a Future object to communicate results/exceptions
            future = Future()

            # Define the function to run in the secondary thread
            def test_function():
                try:
                    # Call the decorated function
                    func(baseclass, window, **kwargs)
                    future.set_result("Completed Successfully")
                except Exception as e:
                    # Set the exception in the Future
                    future.set_exception(e)
                finally:
                    # Close the WebView window
                    if window is not None:
                        window.destroy()

            # Define a function to start the thread
            def start_test_function():
                # Run the function in a secondary thread
                with ThreadPoolExecutor() as executor:
                    executor.submit(test_function)

            # Start the WebView and execute the thread alongside it
            webview.start(start_test_function)

            # Retrieve the result or exception from the Future
            future.result()

        return wrapper
    return decorator