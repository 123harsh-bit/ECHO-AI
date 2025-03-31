import multiprocessing

workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'gevent'
timeout = 120
keepalive = 5
bind = '0.0.0.0:5000'
max_requests = 1000
max_requests_jitter = 50
