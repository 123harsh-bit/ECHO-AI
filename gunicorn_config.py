try:
    from gevent import version_info
    if version_info[0] < 1 or (version_info[0] == 1 and version_info[1] < 4):
        raise RuntimeError("gevent worker requires gevent 1.4 or higher")
except ImportError:
    raise RuntimeError("gevent package not found")

workers = 2  # Reduced for smaller instances
worker_class = 'gevent'
timeout = 120
bind = '0.0.0.0:5000'
