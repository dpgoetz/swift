import os
import errno
import sys
import sqlite3
import random
from time import time
from tempfile import mkstemp
from contextlib import contextmanager, closing
from eventlet import Timeout
from swift.common.db import GreenDBConnection, DatabaseAlreadyExists
from swift.common.utils import renamer, lock_parent_directory, \
    get_logger, remove_file, readconf


DB_SCHEMA = '''
CREATE TABLE IF NOT EXISTS error_limiter (
    node_id TEXT NOT NULL,
    time_window INTEGER NOT NULL,
    request INTEGER DEFAULT 0,
    error INTEGER DEFAULT 0,
    PRIMARY KEY (node_id, time_window));

CREATE INDEX IF NOT EXISTS ix_time_window ON error_limiter (time_window);
CREATE INDEX IF NOT EXISTS ix_node_id ON error_limiter (node_id);
'''


class ErrorLimiter(object):

    def __init__(self, conf_path, logger=None):
        """
        Raises OSError if can't make directory to keep databases
        """
        if conf_path and conf_path.lower().strip() != 'default':
            conf = readconf(conf_path, 'error_limit')
        else:
            conf = {}
        self.db_dir = conf.get('dir_path', '/var/run/swift/error-limiter')
        try:
            os.makedirs(self.db_dir)
        except OSError as err:
            if err.errno != errno.EEXIST:
                raise
        self.error_key = conf.get('error_key', '%(ip)s_%(port)s')
        self.db_lifetime = int(conf.get('db_lifetime', 60 * 60 * 12))
        self.window_size = int(conf.get('window_size', 60))
        self.timeout = float(conf.get('db_timeout', .5))
        self.lookback_windows = int(conf.get('lookback_windows', 5))
        self.max_error_limit_perc = float(conf.get('max_error_limit_perc', .9))
        self.allow_to_kick = int(conf.get('allow_to_kick', 1))
        self.cur_db_path = None
        self.conn = None
        if logger:
            self.logger = logger
        else:
            self.logger = get_logger(conf, log_route='error_limiter')

    def get_db_path(self, offset=0):
        return os.path.join(
            self.db_dir,
            'error_limiter.%d.db' % (int(time() / self.db_lifetime) - offset))

    def get_current_state(self):
        """
        Will pull out the error limited nodes out of the
        database and return them as a list.
        """
        min_time = self.get_min_time()
        with self.get_conn() as conn:
            query = '''
            SELECT node_id, time_window, request, error
            FROM error_limiter
            WHERE time_window > ?
            ORDER BY time_window DESC'''
            try:
                curs = conn.execute(query, (min_time,))
                node_to_dict = self.process_error_limit_rows(curs)
                return node_to_dict
            except sqlite3.OperationalError, e:
                if 'no such table: error_limiter' in str(e):
                    return []
                raise

    def populate_from_old_db(self, cur_conn):
        """
        Will pull out data from previous sqlite db and populate this database
        with its most recent data. Will also attempt to delete older databases
        """
        previous_db_path = self.get_db_path(offset=1)

        with self.get_conn() as conn:
            conn.execute('ATTACH DATABASE ? AS previous', (previous_db_path,))
            min_previous_time = int(
                time() - (self.window_size * self.lookback_windows))
            min_previous_time_window = self.get_window() - self.lookback_windows
            try:
                conn.execute('BEGIN TRANSACTION')
                curs = conn.execute('''
                select * from previous.error_limiter
                ''')
                min_time_result = conn.execute('''
                SELECT MIN(time_window) as min_time FROM error_limiter
                ''').fetchone()[0]
                if min_time_result:
                    min_cur_time_window = min_time_result
                else:
                    min_cur_time_window = int(time()) + 1

                curs = conn.execute('''
                INSERT INTO error_limiter
                (node_id, time_window, request, error)
                SELECT p.node_id, p.time_window, p.request, p.error
                FROM previous.error_limiter p WHERE
                p.time_window < ?
                AND p.time_window > ?
                ''', (min_cur_time_window, min_previous_time_window,))
                conn.commit()
            except sqlite3.OperationalError, e:
                if 'no such table: previous.error_limiter' in str(e):
                    return
                raise

    def make_db_connection(self, loc):
        conn = sqlite3.connect(loc, check_same_thread=False,
                               factory=GreenDBConnection, timeout=self.timeout)

        with closing(conn.cursor()) as cur:
            cur.execute('PRAGMA synchronous = OFF')
            cur.execute('PRAGMA temp_store = MEMORY')
            cur.execute('PRAGMA journal_mode = MEMORY')
        return conn

    def initialize(self, db_path):
        """
        Create the DB
        """
        fd, tmp_db_file = mkstemp(suffix='.tmp', dir=self.db_dir)
        need_to_rm = True
        try:
            os.close(fd)
            conn = self.make_db_connection(tmp_db_file)
            conn.executescript(DB_SCHEMA)
            conn.commit()
            conn.close()
            with lock_parent_directory(db_path, self.timeout):
                if os.path.exists(db_path):
                    conn = self.make_db_connection(db_path)
                    res = conn.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND "
                        "name='error_limiter'").fetchall()
                    if len(res):
                        raise DatabaseAlreadyExists(db_path)
                renamer(tmp_db_file, db_path)
                need_to_rm = False
                if self.conn:
                    self.conn.close()
                self.conn = self.make_db_connection(db_path)
                self.cur_db_path = db_path
        finally:
            if need_to_rm:
                remove_file(tmp_db_file)

    def possibly_rm(self, conn, exc_type, exc_value, exc_traceback):
        if 'database previous is already in use' in exc_value:
            return
        exc_hint = exc_value
        if 'database disk image is malformed' in str(exc_value):
            exc_hint = 'malformed'
        elif 'file is encrypted or is not a database' in str(exc_value):
            exc_hint = 'corrupted'
        self.logger.error('Removing error limiter db: %s because of %s' % (
            self.cur_db_path, exc_hint))

        remove_file(self.cur_db_path)
        self.cur_db_path = None

    def remove_old_db(self):
        db_path = self.get_db_path(offset=2)
        remove_file(db_path)

    @contextmanager
    def get_conn(self, force_init=False):
        db_path = self.get_db_path()
        if force_init or db_path != self.cur_db_path:

            if self.conn:
                self.conn.close()
            self.conn = None
            try:
                self.initialize(db_path)
                try:
                    self.populate_from_old_db(db_path)
                except Exception as e:
                    self.logger.debug('Error populate_from_old_db: %s' % e)
                self.remove_old_db()
            except DatabaseAlreadyExists:
                pass

        if not self.conn:
            self.conn = self.make_db_connection(db_path)
            self.cur_db_path = db_path

        conn = self.conn
        self.conn = None
        try:
            yield conn
            conn.rollback()
            if self.conn is not None:
                self.logger.debug('Closing connection made since yield')
                try:
                    self.conn.close()
                except Exception as e:
                    self.logger.debug(
                        'Error closing connection made since yield: %s' % e)

            self.conn = conn
        except sqlite3.OperationalError, e:
            if 'no such table: error_limiter' in str(e):
                self.initialize(db_path)
            else:
                raise
        except sqlite3.DatabaseError:
            try:
                conn.close()
            except Exception:
                pass
            self.possibly_rm(conn, *sys.exc_info())
        except (Exception, Timeout):
            conn.close()
            raise

    def get_window(self):
        return int(time() / self.window_size)

    def record_action(self, node, request_or_error):
        node_id = self.get_node_id(node)
        if node_id is None:
            return
        time_window = self.get_window()
        if request_or_error not in ['request', 'error']:
            raise ValueError(
                'request_or_error must be either "request" or "error"')

        with self.get_conn() as conn:
            conn.execute('BEGIN TRANSACTION')
            curs = conn.cursor()
            up = curs.execute(
                'UPDATE error_limiter SET %s = %s + 1 '
                'WHERE node_id = ? and time_window = ?' %
                (request_or_error, request_or_error),
                (node_id, time_window))
            if not up.rowcount:
                curs.execute(
                    'INSERT OR IGNORE INTO error_limiter '
                    '(node_id, time_window, %s) '
                    'VALUES (?, ?, 1)' % request_or_error,
                    (node_id, time_window))
            conn.commit()

    def get_node_id(self, node):
        """
        :params node: a dict like object that supplies the key needed in
                      self.error_key
        :returns: the node_id key for the given node or None
                  if it cannot be built.
        """
        try:
            return self.error_key % node
        except KeyError:
            self.logger.error(
                'Node %s does not supply required keys for: %s' % (
                node, self.error_key))
        return None

    def process_error_limit_rows(self, curs):
        num_results = self.lookback_windows
        node_to_dict = {}

        for row in curs:
            row_node_id, time_window, num_reqs, num_errors = row

            if row_node_id not in node_to_dict:
                node_to_dict[row_node_id] = {}


            total_reqs = node_to_dict[row_node_id].get('total_reqs', 0)
            total_errors = node_to_dict[row_node_id].get('total_errors', 0)
            num_results = node_to_dict[row_node_id].get('num_results', 1)
            numerator = node_to_dict[row_node_id].get('numerator', 0.0)
            denominator = node_to_dict[row_node_id].get('denominator', 0.0)

            weight = round(float(self.lookback_windows) / num_results)

            numerator += num_errors * weight
            denominator += num_reqs * weight
            total_reqs += num_reqs
            total_errors += num_errors
            num_results += 1

            node_to_dict[row_node_id] = {
                'numerator': numerator,
                'denominator': denominator,
                'num_results': num_results,
                'total_reqs': total_reqs,
                'total_errors': total_errors}

        return node_to_dict

    def get_min_time(self):
        time_window = self.get_window()
        return time_window - self.window_size * self.lookback_windows

    def is_error_limited(self, node):
        node_id = self.get_node_id(node)
        if node_id is None:
            return
        min_time = self.get_min_time()

        query = '''
        SELECT node_id, time_window, request, error
        FROM error_limiter
        WHERE node_id = ?
        AND time_window >= ?
        ORDER BY time_window DESC
        LIMIT ?'''

        with self.get_conn() as conn:
            curs = conn.execute(
                query, (node_id, min_time, self.lookback_windows))
            node_to_dict = self.process_error_limit_rows(curs)

            numerator = node_to_dict.get(node_id, {}).get('numerator', 0.0)
            denominator = node_to_dict.get(node_id, {}).get('denominator', 0.0)

            if denominator <= 0:
                # no results
                return False
            weighted_average = min(
                numerator / denominator, self.max_error_limit_perc)

            return random.random() < weighted_average
