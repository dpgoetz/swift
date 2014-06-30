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

import os
import unittest
import tempfile
import time
import sqlite3
from mock import patch
from swift.common.error_limiter import ErrorLimiter
from swift.common.utils import json


class TestErrorLimiter(unittest.TestCase):
    def setUp(self):

        self.db_dir = tempfile.mkdtemp()
        self.conf_path = os.path.join(self.db_dir, 'el.conf')
        with open(self.conf_path, 'w') as fd:
            fd.write('[error_limit]\ndir_path=%s\n' % self.db_dir)

        self.limiter = ErrorLimiter(self.conf_path)
        self.limiter.get_db_path = self.my_get_db_path
        self.start_time = int(time.time())
        self.my_offset = 0

    def tearDown(self):
        self.my_offset = 0
        for db_file in os.listdir(self.limiter.db_dir):
            os.remove(os.path.join(self.limiter.db_dir, db_file))
        os.rmdir(self.db_dir)

    def test_read_conf(self):
        c_path = os.path.join(self.limiter.db_dir, 'hat')
        with open(c_path, 'w') as f:
            f.write('[error_limit]\nwindow_size = 88\n'
                    'dir_path=%s' % self.db_dir)
        limiter = ErrorLimiter(c_path)
        self.assertEqual(limiter.window_size, 88)

    def my_get_db_path(self, offset=0):
        total_offset = self.my_offset + offset
        return os.path.join(
            self.limiter.db_dir,
            'error_limiter.%d.db' % (
                int(self.start_time / self.limiter.db_lifetime)
                - total_offset))

    def test_record_action_invalid_type(self):
        self.assertRaises(
            ValueError, self.limiter.record_action,
            {'ip': '1.2.3.4', 'port': 6000}, 'hello')

    def test_record_action_invalid_node(self):
        self.assertEqual(
            self.limiter.get_node_id({'ip': '1.2.3.4', 'no_port': 6000}), None)
        self.assertEqual(
            self.limiter.record_action(
                {'ip': '1.2.3.4', 'no_port': 6000}, 'request'), None)

    def test_is_error_limited_invalid_node(self):
        self.assertEqual(
            self.limiter.is_error_limited(
                {'ip': '1.2.3.4', 'no_port': 6000}), None)

    def test_record_action(self):
        node = {'ip': '1.2.3.4', 'port': 6000}
        self.limiter.record_action(node, 'request')
        self.assertEqual(self.limiter.is_error_limited(node), False)
        self.assertEqual(
            self.limiter.get_current_state()['1.2.3.4_6000']['total_reqs'], 1)

    def test_show_error_limited_nodes(self):
        node = {'ip': '1.2.3.4', 'port': 6000}
        self.limiter.record_action(node, 'request')
        self.assertEqual(self.limiter.is_error_limited(node), False)
        data = json.loads(
            self.limiter.show_error_limited_nodes(output_format='json'))
        self.assertEqual(data['1.2.3.4_6000']['total_reqs'], 1)
        self.assertTrue('0.00%' in self.limiter.show_error_limited_nodes())

    def test_is_error_limiter_lookback_window(self):
        node = {'ip': '1.2.3.4', 'port': 6000}
        with self.limiter.get_conn() as conn:
            conn.execute('BEGIN TRANSACTION')
            curs = conn.cursor()
            time_window = self.limiter.get_window()
            for i in range(self.limiter.lookback_windows):
                curs.execute(
                    'INSERT INTO error_limiter '
                    '(node_id, time_window, request, error) '
                    'VALUES (?, ?, 10, 5)',
                    ('1.2.3.4_6000', time_window - i))
            curs.execute(
                'INSERT INTO error_limiter '
                '(node_id, time_window, request, error) '
                'VALUES (?, ?, 100, 100)',
                ('1.2.3.4_6000',
                 time_window - self.limiter.lookback_windows - 1))
            conn.commit()
        with patch('random.random', return_value=.49):
            self.assertTrue(self.limiter.is_error_limited(node))
        with patch('random.random', return_value=.50):
            self.assertFalse(self.limiter.is_error_limited(node))

    def test_is_error_limiter_max_limit(self):
        node = {'ip': '1.2.3.4', 'port': 6000}
        with self.limiter.get_conn() as conn:
            conn.execute('BEGIN TRANSACTION')
            curs = conn.cursor()
            time_window = self.limiter.get_window()
            curs.execute(
                'INSERT INTO error_limiter '
                '(node_id, time_window, request, error) '
                'VALUES (?, ?, 100, 100)',
                ('1.2.3.4_6000',
                 time_window))
            conn.commit()
        with patch('random.random',
                   return_value=self.limiter.max_error_limit_perc - .1):
            self.assertTrue(self.limiter.is_error_limited(node))
        with patch('random.random',
                   return_value=self.limiter.max_error_limit_perc):
            self.assertFalse(self.limiter.is_error_limited(node))

    def test_is_error_limiter_running_average(self):
        node = {'ip': '1.2.3.4', 'port': 6000}
        with self.limiter.get_conn() as conn:
            conn.execute('BEGIN TRANSACTION')
            curs = conn.cursor()
            time_window = self.limiter.get_window()
            curs.execute(
                'INSERT INTO error_limiter '
                '(node_id, time_window, request, error) '
                'VALUES (?, ?, 10, 10)',
                ('1.2.3.4_6000',
                 time_window))
            curs.execute(
                'INSERT INTO error_limiter '
                '(node_id, time_window, request, error) '
                'VALUES (?, ?, 10, 5)',
                ('1.2.3.4_6000',
                 time_window - 1))
            conn.commit()
        with patch('random.random',
                   return_value=.81):
            self.assertTrue(self.limiter.is_error_limited(node))
        with patch('random.random',
                   return_value=.82):
            self.assertFalse(self.limiter.is_error_limited(node))

    def test_populate_from_old_db_no_min_time(self):
        self.my_offset = 1
        with self.limiter.get_conn() as conn:
            conn.execute('BEGIN TRANSACTION')
            curs = conn.cursor()
            time_window = self.limiter.get_window() - 1
            curs.execute(
                'INSERT INTO error_limiter '
                '(node_id, time_window, request, error) '
                'VALUES (?, ?, 10, 10)',
                ('1.2.3.4_6000',
                 time_window))
            curs.execute(
                'INSERT INTO error_limiter '
                '(node_id, time_window, request, error) '
                'VALUES (?, ?, 10, 5)',
                ('1.2.3.4_6000',
                 time_window - 1))
            conn.commit()
        prev_state = self.limiter.get_current_state()
        self.my_offset = 0
        cur_state = self.limiter.get_current_state()
        self.assertEqual(prev_state, cur_state)

    def test_populate_from_old_db_with_min_time(self):
        node = {'ip': '1.2.3.4', 'port': 6000}
        other_limiter = ErrorLimiter(self.conf_path)
        other_limiter.db_dir = tempfile.mkdtemp()
        other_limiter.get_db_path = self.my_get_db_path

        self.my_offset = 1
        with other_limiter.get_conn() as conn:
            conn.execute('BEGIN TRANSACTION')
            curs = conn.cursor()
            time_window = other_limiter.get_window() - 1
            curs.execute(
                'INSERT INTO error_limiter '
                '(node_id, time_window, request, error) '
                'VALUES (?, ?, 10, 10)',
                ('1.2.3.4_6000',
                 time_window))
            curs.execute(
                'INSERT INTO error_limiter '
                '(node_id, time_window, request, error) '
                'VALUES (?, ?, 10, 5)',
                ('1.2.3.4_6000',
                 time_window - 1))
            conn.commit()
        prev_state = other_limiter.get_current_state()
        self.my_offset = 0

        other_limiter.initialize(other_limiter.get_db_path())
        conn = other_limiter.make_db_connection(other_limiter.get_db_path())
        conn.execute(
            'INSERT INTO error_limiter '
            '(node_id, time_window, request, error) '
            'VALUES (?, ?, 1, 0)',
            ('1.2.3.4_6000',
             time_window))
        conn.commit()
        conn.close()

        self.limiter.populate_from_old_db(
            self.limiter.make_db_connection(self.limiter.get_db_path()))
        # this should only pull in the time_window-1 values
        cur_state = self.limiter.get_current_state()
        self.assertNotEqual(prev_state, cur_state)
        self.assertEqual(cur_state['1.2.3.4_6000']['total_reqs'], 11)
        self.assertEqual(cur_state['1.2.3.4_6000']['total_errors'], 5)
        with patch('random.random',
                   return_value=.42):
            self.assertTrue(self.limiter.is_error_limited(node))
        with patch('random.random',
                   return_value=.43):
            self.assertFalse(self.limiter.is_error_limited(node))

    def test_get_conn_exception_handling_re_init(self):
        with self.limiter.get_conn() as conn:
            conn.execute('drop table error_limiter')
            conn.commit()
        node = {'ip': '1.2.3.4', 'port': 6000}
        self.limiter.record_action(node, 'request')
        self.limiter.record_action(node, 'request')
        cur_state = self.limiter.get_current_state()
        self.assertEqual(cur_state['1.2.3.4_6000']['total_reqs'], 1)

    def test_get_conn_exception_handling_database_error(self):
        self.assertFalse(os.path.exists(self.limiter.get_db_path()))
        with self.limiter.get_conn():
            self.assertTrue(os.path.exists(self.limiter.get_db_path()))
            raise sqlite3.DatabaseError()
        self.assertFalse(os.path.exists(self.limiter.get_db_path()))

    def test_get_current_state_exception_handling(self):
        def my_func(*args):
            raise sqlite3.OperationalError('no such table: error_limiter')
        with patch.object(self.limiter, 'process_error_limit_rows', my_func):
            self.assertEqual(self.limiter.get_current_state(), [])

        def my_func(*args):
            raise sqlite3.OperationalError()
        with patch.object(self.limiter, 'process_error_limit_rows', my_func):
            self.assertRaises(sqlite3.OperationalError,
                              self.limiter.get_current_state)

    def test_get_conn_exception_handling_exception(self):
        self.assertFalse(os.path.exists(self.limiter.get_db_path()))
        exception_raised = False
        try:
            with self.limiter.get_conn():
                self.assertTrue(os.path.exists(self.limiter.get_db_path()))
                raise Exception()
        except Exception:
            exception_raised = True
        self.assertTrue(exception_raised)
        self.assertEqual(self.limiter.conn, None)
        self.assertTrue(os.path.exists(self.limiter.get_db_path()))

    def test_get_conn_exception_handling_new_conn_made(self):
        got_closed = [0]

        def my_close():
            got_closed[0] += 1

        with self.limiter.get_conn() as conn:
            conn.close = my_close
            self.assertEqual(self.limiter.conn, None)
            with self.limiter.get_conn() as conn:
                conn.close = my_close
                self.assertEqual(self.limiter.conn, None)
            self.assertNotEqual(self.limiter.conn, None)
        self.assertNotEqual(self.limiter.conn, None)
        self.assertEqual(got_closed[0], 1)

if __name__ == '__main__':
    unittest.main()
