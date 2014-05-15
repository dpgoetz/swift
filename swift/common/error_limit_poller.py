# Copyright (c) 2010-2014 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from random import random, shuffle
from eventlet import sleep, greenthread



class ErrorLimiter(object)

    def __init__(self, limit_window, ignore_ratio, memcache, logger):
        self.window = limit_window
        self.ignore_ratio = ignore_ratio
        self.limit_dict = {'running_average': {}}
        self.logger = logger
        self.memcache = memcache
        # these should ad up to 1
        self.current_weight = .5
        self.prev_weight = .3
        self.running_weight = .2

    def _memcache_update(self):
        """
        will walk though self.limit_dict[prev_rounded_time] and update
        memcache with its values,
        Will query memcache and update limit_dict with corresponding
        values in memcache. Will also update memcache with limit_dict
        data.

        There is a small race condition between the set/get with this function-
        however it should mostly work which should be sufficient for this
        application.
        """
        while True:
            rounded_time = int(time()) / self.window
            prev_rounded_time = rounded_time - 1
            if prev_rounded_time not in self.limit_dict:
                return

            prev_limit_keys = self.limit_dict[prev_rounded_time].keys()
            shuffle(prev_limit_keys)
            for limit_key in prev_limit_keys:
                prev_touches, prev_errors, sent_to_memcache = \
                    self.limit_dict[prev_rounded_time][limit_key]
                if sent_to_memcache:
                    continue
                memcache_key = 'swift/error_limit/%s' % limit_key
                mval_tup = self.memcache.get(memcache_key)
                if mval_tup:
                    touches, errors = mval_tup
                    prev_touches += touches
                    prev_errors += errors
                mval_tup = self.memcache.set(
                    memcache_key, (prev_touches, prev_errors),
                    time=self.window)
                self.limit_dict[prev_rounded_time][limit_key] = (
                    prev_touches, prev_errors, True)
                sleep(.1 + random() / 10)
            sleep(self.window / 2)

    def keep_insync_with_memcache(self):
        """
        """
        greenthread.spawn_n(self._memcache_update)

    def report_timeout(self, node):
        """
        """
        timeout_key = '%s_%s' % (node['ip'], node['port'])
        rounded_time = int(time()) / self.window
        if rounded_time not in self.limit_dict:
            self.limit_dict[rounded_time] = {}

        # only increment num_errors, timeout_key's touches should have been
        # incremented when asked if is_error_limited, if its not set- assume
        # that is_error_limited was called on previous time window
        num_touches, num_errors, sent_to_memcache = \
            self.limit_dict[rounded_time].get(timeout_key, (1.0, 0, False))
        self.limit_dict[rounded_time][timeout_key] = \
            (num_touches, num_errors + 1.0, sent_to_memcache)

    def is_error_limited(self, node):
        """
        If the node's ip has has been timing out recently then
        limit the # of requests going to it based on how much
        it has been failings.
        """
        timeout_key = '%s_%s' % (node['ip'], node['port'])
        rounded_time = int(time()) / self.window
        prev_rounded_time = rounded_time - 1

        if rounded_time not in self.limit_dict:
            # entered a new time window- init it and average
            # prev_rounded_time-1 into historical average
            self.limit_dict[rounded_time] = {}
            expired_data = self.limit_dict.pop(prev_rounded_time - 1, None)
            if expired_data:
                touches, errors, junk = expired_data
                was_run_average = \
                    self.limit_dict['running_average'].get(timeout_key, 1.0)
                new_average = (was_run_average + errors / touches) / 2.0
                self.limit_dict['running_average'][timeout_key] = new_average

        cur_touches, cur_errors, junk = \
            self.limit_dict[rounded_time].get(timeout_key, (0, 0, False))
        current_average = cur_errors / cur_touches

        prev_average = 0.0
        if prev_rounded_time in self.limit_dict and \
                timeout_key in self.limit_dict[prev_rounded_time]:
            touches, errors, j = \
                self.limit_dict[prev_rounded_time][timeout_key]
            prev_average = errors / touches

        running_average = \
            self.limit_dict['running_average'].get(timeout_key, 0.0)

        evaluated_average = current_average * self.current_weight + \
                            prev_average * self.prev_weight + \
                            running_average * self.running_weight

        if evaluated_average > self.ignore_ratio and \
                random() < evaluated_average:
            self.logger.debug('Error limiting %s, %d errors to %d hits' % (
                timeout_key, total_errors, total_touches))
            return True

        # going ahead with request, set current counter
        self.limit_dict[rounded_time][timeout_key] = \
            (cur_touches + 1.0, cur_errors, False)
        return False
