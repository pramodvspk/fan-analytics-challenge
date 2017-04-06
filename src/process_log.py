import timeit
import re
import datetime
import heapq
import sys
from collections import defaultdict
from collections import Counter
from collections import defaultdict
from collections import namedtuple
from collections import defaultdict
from collections import OrderedDict

APACHE_ACCESS_LOG_PATTERN = '^(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+)\s*(\S*)" (\d{3}) (\S+)'

month_map = {'Jan': 1, 'Feb': 2, 'Mar':3, 'Apr':4, 'May':5, 'Jun':6, 'Jul':7,
    'Aug':8,  'Sep': 9, 'Oct':10, 'Nov': 11, 'Dec': 12}

def parse_apache_time(s):
	""" Convert Apache time format into a Python datetime object
	Args:
	s (str): date and time in Apache time format
	Returns:
	datetime: datetime object
	"""
	return datetime.datetime(int(s[7:11]),
							month_map[s[3:6]],
							int(s[0:2]),
							int(s[12:14]),
							int(s[15:17]),
							int(s[18:20]))

# A nametuple that encodes required features from the Apache log line
Access = namedtuple('Access',
	['host_name', 'date_time',
	'end_point', 'response_code', 'content_size', 'log_line'])

# A namedtuple that encodes required features for calculating the blocked requests
HostAccess = namedtuple('HostAccess',['date_time','response_code', 'log_line'])

class Hits_ordering(object):
    __slots__ = ()
    def __lt__(self, other):
    	if self.hits == other.hits:
    		return self.datetime > other.datetime
    	else:
    		return self.hits < other.hits

# A namedtuple that encodes required features for calculating the number of hits in a window
class Hits(Hits_ordering, namedtuple('Hits',['hits','datetime'])):
    pass

# Dictionaries that hold data required to implement the features
host_count = defaultdict(int)
resource_count = defaultdict(int)
hits_time = OrderedDict()
host_access_dict = defaultdict(list)

# Global variables
log_start_time = None
timer = None

def parse_apache_log_line(log_line):
	""" Parses a Apache log line into a Access named tuple
    Args:
        log_line (str): log line in Apache Log format
    Returns:
        access: An Access named tuple that contains the parsed fields, if parsing failed returns None
    """
	match = re.match(APACHE_ACCESS_LOG_PATTERN, log_line)
	if match != None:
		size_field = match.group(9)
		if size_field == '-':
			size = long(0)
		else:
			size = long(match.group(9))
		return Access(
	        host_name      = match.group(1),
	        date_time      = parse_apache_time(match.group(4)),
	        end_point      = match.group(6),
	        response_code  = int(match.group(8)),
	        content_size   = size,
	        log_line       = log_line
	    )
	else:
	 	return None

def calculate_most_active_hosts(parsed_log_line):
	""" Parses the parsed log line, extracts the host name and updates the dictionary that calculates the number of times each host accessed the website
    Args:
        parsed_log_line (namedtuple): Access namedtuple
    """
	host_name = parsed_log_line.host_name
	host_count[host_name] += 1

def find_most_active_hosts():
	""" From the dictionary that has calculated the number of times host accessed the website, it finds the top 10 hosts and writes it into a file 'hosts.txt'
	"""
	top_10_hosts= Counter(host_count).most_common(10)
	output_file = open(sys.argv[2], 'w')
	for host in top_10_hosts:
		print>>output_file, host[0] + "," + str(host[1])

def calculate_most_bandwidth_resources(parsed_log_line):
	""" Parses the parsed log line, extracts the content size and the end point and updates the dictionary
    Args:
        parsed_log_line (namedtuple): Access namedtuple
    """
	end_point = parsed_log_line.end_point
	content_size = parsed_log_line.content_size
	resource_count[end_point] += content_size

def find_most_bandwidth_resources():
	""" From the dictionary that has calculated the most bandwith consumer resource endpoints it finds the top 10 hosts and writes it into a file 'resources.txt'
	"""
	top_10_resources = Counter(resource_count).most_common(10)
	output_file = open(sys.argv[4], 'w')
	for resource in top_10_resources:
		print>>output_file, resource[0]

def find_starting_log_time():
	""" Finds the time from when the logs have started
	Returns:
		start_time (datetime): The datetime object that signifies when the logs have started
	"""
	with open(sys.argv[1]) as file:
		for line in file:
			start_time = parse_apache_log_line(line).date_time
			if start_time != None:
				return start_time
			else:
				continue

def calculate_busiest_times(parsed_log_line):
	""" Parses the parsed log line, calculates the number of hits occuring on the website at each time and updates a dictionary
    Args:
        parsed_log_line (namedtuple): Access namedtuple
    """
	line_time = parsed_log_line.date_time
	global timer
	if timer != parsed_log_line.date_time:
		while(timer != line_time):
			timer = timer + datetime.timedelta(seconds=1)
			hits_time[timer] = 0
	endTimer = timer
	if timer in hits_time:
		hits_time[timer] += 1
	else:
		hits_time[timer] = 1

def parse_time(time, fmt='%d/%b/%Y:%H:%M:%S -0400'):
	""" Parses the datetime object into the format specified
    Args:
        time (datetime): time that needs to be formatted
        fmt (str) : format required
    """
	return time.strftime(fmt)


def find_busiest_windows():
	""" Finds the busiest 60 minute windows from the dictionary that captured the hits for each second and writes it into a file 'hours.txt'
    """
    # The initial [first] 60 minute window end time
	initial_window_end = log_start_time + datetime.timedelta(seconds=3600)
	initial_window_hits = 0

	# Calculate the hits till the initial[first] window end time
	temp = log_start_time
	while(temp < initial_window_end and temp in hits_time):
		initial_window_hits += hits_time[temp]
		temp += datetime.timedelta(seconds=1)

	# A heap of size 10 that stores the top 10 hit windows
	hits_heap = []
	heapq.heappush(hits_heap, Hits(hits=initial_window_hits, datetime=log_start_time))

	temp = log_start_time
	i = 1

	# Iterate through every second and calculate the number of hits using the Sliding window algorithm
	while(i<len(hits_time)):
		initial_window_hits -= hits_time[temp]
		temp += datetime.timedelta(seconds=1)
		temp_end = temp + datetime.timedelta(seconds=3600)
		if temp_end in hits_time:
			initial_window_hits += hits_time[temp_end]

		# Since only the top 10 time windows needs to be stored check the top most element[hits] in the heap and only if the current window hits are greater that the top most element then push it into the heap else continue
		if len(hits_heap) < 10:
			heapq.heappush(hits_heap, Hits(hits=initial_window_hits, datetime=temp))
		else:
			if initial_window_hits > hits_heap[0].hits:
				heapq.heappushpop(hits_heap, Hits(hits=initial_window_hits, datetime=temp))
		i += 1

	top_10_hit_times = heapq.nlargest(10, hits_heap)
	output_file = open(sys.argv[3], 'w')
	for hit_time in top_10_hit_times:
		print>>output_file, parse_time(hit_time[1]) + ","+ str(hit_time[0])

def calculate_host_access(parsed_log_line):
	""" Parses the parsed log line, and captures the date time and the response code of each access and stores them in a list
    Args:
        parsed_log_line (namedtuple): Access namedtuple
    """
	date_time = parsed_log_line.date_time
	response_code = parsed_log_line.response_code
	log_line = parsed_log_line.log_line
	host_name = parsed_log_line.host_name

	host_access = HostAccess(date_time=date_time, response_code=response_code, log_line=log_line)

	host_access_dict[host_name].append(host_access)

def find_blocked_requests():
	""" Iterates through the host access dictionary and finds the set of blocked requests for each host
    """
	output_file = open(sys.argv[5], 'w')
	for key, value in host_access_dict.iteritems():
		current_failed_attempts = 0
		window_timer_set = False
		is_session_started = False
		latest_failed_attempt_time = None
		for i in range(len(value)):
			current_tuple = value[i]
			#Check if the 5 minutes blocking session is started
			if is_session_started and current_tuple.date_time<=session_end_time:
			#Since the session is started put all the loglines into the outputList
				print>>output_file, current_tuple.log_line
			else:
				#The 5 minutes blocking session is not started
				#So check if the 20 seconds Window timer to get the 3 consecutive failed attempts is set and if the currentTime is less than the window end time
				if window_timer_set and current_tuple.date_time<=window_end_time:
				#Since the windowtimer is set, check for the 401 response code and update the latest failed attempt time and update the current failed attempts count 
					if current_tuple.response_code == 401:
						latest_failed_attempt_time = current_tuple.date_time
						current_failed_attempts += 1
						#if the current failed attempts are 3, then calculate the session end time by adding the latestfailed attempt time plus 5 minutes
						if current_failed_attempts == 3:
							session_end_time = current_tuple.date_time + datetime.timedelta(minutes=5)
							is_session_started = True
					else:
						#Since the response code is not 401, set the current failed attempts to 0 and stop the timer
						window_timer_set = False
						current_failed_attempts = 0
						#Case when the timer is not set and the first time a failed attempt is being encountered
				else:
					if current_tuple.response_code == 401:
					#Switch on the windowTimer and set the current failed attempts to 1
						window_timer_set = True
						window_end_time = current_tuple.date_time + datetime.timedelta(seconds =20)

						current_failed_attempts = 1


if __name__ == "__main__":
	log_start_time = find_starting_log_time()
	timer = log_start_time
	with open(sys.argv[1]) as file:
		for log_line in file:
			parsed_log_line = parse_apache_log_line(log_line)
			if parsed_log_line != None:
				calculate_most_active_hosts(parsed_log_line)
				calculate_most_bandwidth_resources(parsed_log_line)
				calculate_busiest_times(parsed_log_line)
				calculate_host_access(parsed_log_line)

	find_most_active_hosts()
	find_most_bandwidth_resources()
	find_busiest_windows()
	find_blocked_requests()