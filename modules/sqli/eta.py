# handles ETA (estimated time remaining) tracking during the scan
# It can become more accurate since now it waits until the payloads start
#  but for now it works , Reminder to rebuild it later

class ETA:
    def __init__(self, payloads_dict):
        # takes in a dict of payloads, where values are lists of payload strings
        # adds up the total number of payloads for progress tracking
        self.total = sum(len(lst) for lst in payloads_dict.values())
        self.processed = 0  # how many payloads we've already tested
        self.total_time = 0.0  # total time taken so far

    def update(self, elapsed_time):
        # call this after testing each payload
        self.processed += 1
        self.total_time += elapsed_time  # keep adding time to get an average later

    def avg_time(self):
        # calculate average time per payload
        if self.processed == 0:
            return 0.0  # if nothing's done yet, avoid division by zero
        return self.total_time / self.processed

    def remaining(self):
        # estimate how long it will take to finish the rest
        remaining_payloads = self.total - self.processed
        return remaining_payloads * self.avg_time()

    def percentage(self):
        # return how much of the scan is done as a percentage
        if self.total == 0:
            return 0.0
        return (self.processed / self.total) * 100
