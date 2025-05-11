import socket
import json
import threading
import time
from datetime import datetime, timedelta
import threading
import numpy as np
import psycopg2
from config import conn
from utils import *


if __name__ == "__main__":
    # Start the UDP listener and metadata cleanup threads.
    start_udp_thread()
    start_cleanup_thread()
    print("Syslog UDP listener and metadata cleanup threads started. Awaiting incoming data...")

    # Keep the main thread active.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down.")