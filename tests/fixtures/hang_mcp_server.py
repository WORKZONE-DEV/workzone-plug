"""A stand-in tool server that gets stuck: reads one line, then never answers."""
import sys
import time

sys.stdin.readline()
time.sleep(600)
