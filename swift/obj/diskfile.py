# Copyright (c) 2010-2013 OpenStack, LLC.
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

""" Disk File Interface for Swift Object Server"""

from __future__ import with_statement
import cPickle as pickle
import errno
import os
import time
import uuid
import hashlib
import logging
import traceback
from gettext import gettext as _
from os.path import basename, dirname, exists, getmtime, getsize, join
from tempfile import mkstemp
from contextlib import contextmanager, closing

from xattr import getxattr, setxattr
from eventlet import Timeout
import sqlite3

from swift.common.constraints import check_mount
from swift.common.utils import mkdirs, normalize_timestamp, \
    storage_directory, hash_path, renamer, fallocate, fsync, \
    fdatasync, drop_buffer_cache, ThreadPool, lock_path, write_pickle
from swift.common.exceptions import DiskFileError, DiskFileNotExist, \
    DiskFileCollision, DiskFileNoSpace, DiskFileDeviceUnavailable, \
    PathNotDir
from swift.common.swob import multi_range_iterator
from swift.common.db import GreenDBConnection, DatabaseConnectionError


PICKLE_PROTOCOL = 2
ONE_WEEK = 604800
HASH_FILE = 'hashes.pkl'
HASH_DB = 'hashes.db'
METADATA_KEY = 'user.swift.metadata'


def read_metadata(fd):
    """
    Helper function to read the pickled metadata from an object file.

    :param fd: file descriptor to load the metadata from

    :returns: dictionary of metadata
    """
    metadata = ''
    key = 0
    try:
        while True:
            metadata += getxattr(fd, '%s%s' % (METADATA_KEY, (key or '')))
            key += 1
    except IOError:
        pass
    return pickle.loads(metadata)


def write_metadata(fd, metadata):
    """
    Helper function to write pickled metadata for an object file.

    :param fd: file descriptor to write the metadata
    :param metadata: metadata to write
    """
    metastr = pickle.dumps(metadata, PICKLE_PROTOCOL)
    key = 0
    while metastr:
        setxattr(fd, '%s%s' % (METADATA_KEY, key or ''), metastr[:254])
        metastr = metastr[254:]
        key += 1


def quarantine_renamer(device_path, corrupted_file_path):
    """
    In the case that a file is corrupted, move it to a quarantined
    area to allow replication to fix it.

    :params device_path: The path to the device the corrupted file is on.
    :params corrupted_file_path: The path to the file you want quarantined.

    :returns: path (str) of directory the file was moved to
    :raises OSError: re-raises non errno.EEXIST / errno.ENOTEMPTY
                     exceptions from rename
    """
    from_dir = dirname(corrupted_file_path)
    to_dir = join(device_path, 'quarantined', 'objects', basename(from_dir))
    invalidate_hash(dirname(from_dir))
    try:
        renamer(from_dir, to_dir)
    except OSError, e:
        if e.errno not in (errno.EEXIST, errno.ENOTEMPTY):
            raise
        to_dir = "%s-%s" % (to_dir, uuid.uuid4().hex)
        renamer(from_dir, to_dir)
    return to_dir


def hash_suffix(path, reclaim_age):
    """
    Performs reclamation and returns an md5 of all (remaining) files.

    :param reclaim_age: age in seconds at which to remove tombstones
    :raises PathNotDir: if given path is not a valid directory
    :raises OSError: for non-ENOTDIR errors
    """
    md5 = hashlib.md5()
    try:
        path_contents = sorted(os.listdir(path))
    except OSError, err:
        if err.errno in (errno.ENOTDIR, errno.ENOENT):
            raise PathNotDir()
        raise
    for hsh in path_contents:
        hsh_path = join(path, hsh)
        try:
            files = os.listdir(hsh_path)
        except OSError, err:
            if err.errno == errno.ENOTDIR:
                partition_path = dirname(path)
                objects_path = dirname(partition_path)
                device_path = dirname(objects_path)
                quar_path = quarantine_renamer(device_path, hsh_path)
                logging.exception(
                    _('Quarantined %s to %s because it is not a directory') %
                    (hsh_path, quar_path))
                continue
            raise
        if len(files) == 1:
            if files[0].endswith('.ts'):
                # remove tombstones older than reclaim_age
                ts = files[0].rsplit('.', 1)[0]
                if (time.time() - float(ts)) > reclaim_age:
                    os.unlink(join(hsh_path, files[0]))
                    files.remove(files[0])
        elif files:
            files.sort(reverse=True)
            meta = data = tomb = None
            for filename in list(files):
                if not meta and filename.endswith('.meta'):
                    meta = filename
                if not data and filename.endswith('.data'):
                    data = filename
                if not tomb and filename.endswith('.ts'):
                    tomb = filename
                if (filename < tomb or       # any file older than tomb
                    filename < data or       # any file older than data
                    (filename.endswith('.meta') and
                     filename < meta)):      # old meta
                    os.unlink(join(hsh_path, filename))
                    files.remove(filename)
        if not files:
            os.rmdir(hsh_path)
        for filename in files:
            md5.update(filename)
    try:
        os.rmdir(path)
    except OSError:
        pass
    return md5.hexdigest()

class PickleToDbError(Exception):
    # TODO: put this in exception file
    pass

class CouldNotCreateDatabaseError(Exception):
    # TODO: put this in exception file
    pass

class HashDb(object):
    """
    A class to interface with the hashes databases.
    If you are unsure if the underlying sqlite DB exists or not, build_db
    will create the database and populate it with the existing pickle file
    if it is present. get_hash_data will call build_db if it is needed.
    """

    def __init__(self, partition_dir):
        self.partition_dir = partition_dir
        self.db_file = join(self.partition_dir, HASH_DB)
        self.conn = None
        self.timeout = 10

    def get_db_connection(self, okay_to_create=False):
        """
        Returns a properly configured SQLite database connection.

        :param okay_to_create: if True, create the DB if it doesn't exist
        :returns: DB connection object
        :raises DatabaseConnectionError: on sqlite3 errors and when db doesn't
                                         exists and okay_to_create=False
        """
        try:
            connect_time = time.time()
            conn = sqlite3.connect(self.db_file, check_same_thread=False,
                                   factory=GreenDBConnection,
                                   timeout=self.timeout)
            if self.db_file != ':memory:' and not okay_to_create:
                # attempt to detect and fail when connect creates the db file
                stat = os.stat(self.db_file)
                if stat.st_size == 0 and stat.st_ctime >= connect_time:
                    os.unlink(self.db_file)
                    raise DatabaseConnectionError(self.db_file,
                                                  'DB file created by connect?')
            conn.row_factory = sqlite3.Row
            conn.text_factory = str
            with closing(conn.cursor()) as cur:
                cur.execute('PRAGMA journal_mode = WAL')
        except sqlite3.DatabaseError:
            import traceback
            raise DatabaseConnectionError(self.db_file, traceback.format_exc(),
                                          timeout=self.timeout)
        return conn

    @contextmanager
    def get(self):
        """
        Use with the "with" statement; returns a database connection to
        an existing database.
        """
        if not self.conn:
            if self.db_file != ':memory:' and os.path.exists(self.db_file):
                try:
                    self.conn = self.get_db_connection()
                except (sqlite3.DatabaseError, DatabaseConnectionError):
                    self.check_for_db_corruption(*sys.exc_info())
            else:
                raise DatabaseConnectionError(self.db_file, "DB doesn't exist")
        conn = self.conn
        self.conn = None
        try:
            yield conn
            conn.rollback()
            self.conn = conn
        except sqlite3.DatabaseError:
            try:
                conn.close()
            except Exception:
                pass
            self.check_for_db_corruption(*sys.exc_info())
        except (Exception, Timeout):
            conn.close()
            raise

    def check_for_db_corruption(self, exc_type, exc_value, exc_traceback):
        """
        Examines the error log to check if it was the result of an
        unrecoverable database corruption type error. If so the db will
        be thrown away. It will have to be rebuilt.
        TODO: i should let the next pass rebuild it right? I guess it depends
        on whats going on.  If I have some hashes i could make part of it...
        """
        if 'database disk image is malformed' in str(exc_value):
            exc_hint = 'malformed'
        elif 'file is encrypted or is not a database' in str(exc_value):
            exc_hint = 'corrupted'
        else:
            raise exc_type, exc_value, exc_traceback
        detail = _('Removed %s to %s due to %s database') % \
                  (self.db_dir, quar_path, exc_hint)
        logging.exception(detail)
        os.unlink(self.db_file)
        raise sqlite3.DatabaseError(detail)

    def _make_empty_db(self):
        """
        This assumes the the partition_dir has been locked
        """
        conn = self.get_db_connection(okay_to_create=True)
        conn.executescript("""
            CREATE TABLE suffix_hashes (
                suffix TEXT PRIMARY KEY,
                files_hash TEXT,
                last_modified TEXT DEFAULT (STRFTIME('%s', 'NOW')),
                version INTEGER NOT NULL DEFAULT 0
            );
            CREATE TRIGGER suffix_hashes_update AFTER UPDATE ON suffix_hashes
            BEGIN
                UPDATE suffix_hashes
                SET last_modified = STRFTIME('%s', 'NOW'),
                version = version + 1
                WHERE ROWID = new.ROWID;
            END;
        """)
        conn.commit()
        self.conn = conn

    def _initialize(self, hashes=None, mtime=None):
        """
        This assumes the the partition_dir has been locked
        :params hashes: a list of hashes dicts {'suff': 'abcd',...} to add
        :params mtime: the default last_modified time on hash inserts
        """
        try:
            self._make_empty_db()
        except Exception:
            #TODO: log this
            raise CouldNotCreateDatabaseError()
        if hashes:
            hash_data = []
            mtime = mtime or int(time.time())
            for suffix, hsh in hashes.iteritems():
                hash_data.append((suffix, hsh, str(mtime)))
            with self.get() as conn:
                conn.executemany(
                    """
                    INSERT INTO suffix_hashes
                    (suffix, files_hash, last_modified)
                    VALUES (?, ?, ?)""", hash_data)
                conn.commit()

    def build_db(self):
        """
        Locks the partition_dir, reads in the pickle data, builds the
        new sqlite database out of it and removes the pickle.
        If there is no pickle will build an empty database.
        :raises PickleToDbError: on errors TODO: NOT TRUE
        :raises CouldNotCreateDatabaseError: when can't even create db
        """
        with lock_path(partition_dir):
            if exists(self.db_file):
                return
            hashes_file = join(partition_dir, HASH_FILE)
            hashes, mtime = None, None
            try:
                if exists(hashes_file):
                    with open(hashes_file, 'rb') as fp:
                        hashes = pickle.load(fp)
                    mtime = getmtime(hashes_file)
            except Exception:
                pass
                #TODO: i can't read the pickle- for now just make an empty db

            try:
                self._initialize(hashes, mtime)
                os.unlink(hashes_file)
            except CouldNotCreateDatabaseError:
                pass
                # TODO: what do I do here?


    def get_hash_data(self):
        """
        Returns the data stored in the hashes.db sqlite dbs. If
        the partition does not have a hashes.db then it will lock the dir,
        and build the hashes.db from the hashes.pkl before returning the data.
        Data format is:
        {'abc': {'files_hash': 'abcdef',
                 'mtime': '123456.123',
                 'version': 0}, ...}
        With:
            - abc: the suffix_dir name
            - files_hash: the md5 of the files within the suffix dir
            - mtime: the last modified time of the files_hash
            - version: current version of row, is autoincremented on updates
        :params partition_dir: the partition directory
        TODO: always check for the pickle for old processes hanging around?
        """
        if not exists(self.db_file):
            self.build_db()

        hashes_data = {}
        with self.get() as conn:
            for row in conn.execute("""
                    SELECT suffix, files_hash, last_modified, version
                    FROM suffix_hashes"""):
                hashes_data[row[0]] = {'files_hash': row[1],
                                       'mtime': row[2],
                                       'version': row[3]}
        return hashes_data

    def refresh_hash(self, suffix, version, reclaim_age):
        """
        Writes the data in hashes to the hashes.db
        Will only update the row if the hash version matches.
        :params suffix: the suffix to replace/insert
        :params files_hash: the new hash of the file names in the suffix dir
        :params version: the version that was pulled.
        :raises DatabaseConnectionError: when db doesn't exist
        """
        #TODO : test with files_hash is NULL, and version mismatch (None or not)
        suffix_dir = join(self.partition_dir, suffix)

        files_hash = hash_suffix(suffix_dir, reclaim_age)
        with self.get() as conn:
            conn.execute('BEGIN')
            if version is None:
                # This is a new record.
                try:
                    curs = conn.execute("""
                    INSERT INTO suffix_hashes (suffix, files_hash)
                    VALUES (?, ?)""", (suffix, hash_data['files_hash']))
                    conn.commit()
                except sqlite3.IntegrityError:
                    # This hash was invalidated/overwritten since select. Just
                    # return for now and let the recursive "fix-None" call
                    # clean it up later
                    pass
            else:
                conn.execute("""
                    UPDATE suffix_hashes set files_hash = ?
                    WHERE suffix = ?
                    AND version = ?)""",
                    (files_hash, suffix, version))
                # This may not have been successful. If the version doesn't
                # match anymore then it is either updated with better data
                # (shouldn't happen) or the hash has been invalidated and the
                # recursive "fix-None" call clean it up later
                conn.commit()

    def invalidate_files_hash(self, suffix):
        """
        :params suffix: the suffix whose files_hash will be cleared
        :raises DatabaseConnectionError: when db doesn't exist
        """
        with self.get() as conn:
            conn.execute("""
                UPDATE suffix_hashes set files_hash = NULL
                WHERE suffix = ?""", (suffix,))
            conn.commit()

def invalidate_hash(suffix_dir):
    """
    Invalidates the hash for a suffix_dir in the partition's hashes file.

    :param suffix_dir: absolute path to suffix dir whose hash needs
                       invalidating
    """

    suffix = basename(suffix_dir)
    partition_dir = dirname(suffix_dir)
    hash_db = HashDb(partition_dir)
    try:
        hashes = hash_db.get_hash_data()
    except Exception:
        pass
        # TODO: what do I do here?
    if suffix in hashes and not hashes[suffix]['files_hash']:
        return

    hash_db.invalidate_files_hash(suffix)



def get_hashes(partition_dir, recalculate=None, do_listdir=False,
               reclaim_age=ONE_WEEK):
    """
    Get a list of hashes for the suffix dir.  do_listdir causes it to mistrust
    the hash cache for suffix existence at the (unexpectedly high) cost of a
    listdir.  reclaim_age is just passed on to hash_suffix.

    :param partition_dir: absolute path of partition to get hashes for
    :param recalculate: list of suffixes which should be recalculated when got
    :param do_listdir: force existence check for all hashes in the partition
    :param reclaim_age: age at which to remove tombstones

    :returns: tuple of (number of suffix dirs hashed, dictionary of hashes)
    """

    num_hashed = 0
    force_rewrite = False
    hashes = {}

    if recalculate is None:
        recalculate = []

    hash_db = HashDb(partition_dir)
    try:
        hashes = hash_db.get_hash_data()
    except Exception:
        do_listdir = True
        force_rewrite = True
    # TODO i'm not guaranteed that there is a db here if this threw an Exception
    if do_listdir:
        for suffix in os.listdir(partition_dir):
            if len(suffix) == 3 and suffix not in hashes:
                hash_db.refresh_hash(suffix, None, reclaim_age)
    for suffix in recalculate:
        hash_db.refresh_hash(suffix, version=hashes.getsuffix
                                   reclaim_age=reclaim_age)
        if hsh in hashes:
            hashes[hsh]['files_hash'] = None
        else:
            hashes[hsh] = None
    # hashes is what was pulled out if the db,
    # plus the 'suff': {} of all the new suffixes added to the partition
# also j
    for suffix, hash_dict in hashes.items():
        if not (hash_dict and hash_dict['files_hash']):
            suffix_dir = join(partition_dir, suffix)
            try:
                hash_db.refresh_hash(
                    suffix, hash_suffix(suffix_dir, reclaim_age),
                    hash_dict.get('version', None))
                num_hashed += 1
            except PathNotDir:
                hash_db.delete_hash(suffix, hash_dict.get('version', None))
            except OSError:
                #TODO: should I have a counter for # errors?
                # don't know how i;d use it
                logging.exception(_('Error hashing suffix'))
            #TODO: what do i do about db errors here?
    ret_hashes = dict((suffix, data_dict['files_hash']) for
                      suffix, data_dict in hashes.iteritems())
    return num_hashed, ret_hashes


class DiskWriter(object):
    """
    Encapsulation of the write context for servicing PUT REST API
    requests. Serves as the context manager object for DiskFile's writer()
    method.
    """
    def __init__(self, disk_file, fd, tmppath, threadpool):
        self.disk_file = disk_file
        self.fd = fd
        self.tmppath = tmppath
        self.upload_size = 0
        self.last_sync = 0
        self.threadpool = threadpool

    def write(self, chunk):
        """
        Write a chunk of data into the temporary file.

        :param chunk: the chunk of data to write as a string object
        """

        def _write_entire_chunk(chunk):
            while chunk:
                written = os.write(self.fd, chunk)
                self.upload_size += written
                chunk = chunk[written:]

        self.threadpool.run_in_thread(_write_entire_chunk, chunk)

        # For large files sync every 512MB (by default) written
        diff = self.upload_size - self.last_sync
        if diff >= self.disk_file.bytes_per_sync:
            self.threadpool.force_run_in_thread(fdatasync, self.fd)
            drop_buffer_cache(self.fd, self.last_sync, diff)
            self.last_sync = self.upload_size

    def put(self, metadata, extension='.data'):
        """
        Finalize writing the file on disk, and renames it from the temp file
        to the real location.  This should be called after the data has been
        written to the temp file.

        :param metadata: dictionary of metadata to be written
        :param extension: extension to be used when making the file
        """
        if not self.tmppath:
            raise ValueError("tmppath is unusable.")
        timestamp = normalize_timestamp(metadata['X-Timestamp'])
        metadata['name'] = self.disk_file.name

        def finalize_put():
            # Write the metadata before calling fsync() so that both data and
            # metadata are flushed to disk.
            write_metadata(self.fd, metadata)
            # We call fsync() before calling drop_cache() to lower the amount
            # of redundant work the drop cache code will perform on the pages
            # (now that after fsync the pages will be all clean).
            fsync(self.fd)
            # From the Department of the Redundancy Department, make sure
            # we call drop_cache() after fsync() to avoid redundant work
            # (pages all clean).
            drop_buffer_cache(self.fd, 0, self.upload_size)
            invalidate_hash(dirname(self.disk_file.datadir))
            # After the rename completes, this object will be available for
            # other requests to reference.
            renamer(self.tmppath, join(self.disk_file.datadir,
                                       timestamp + extension))

        self.threadpool.force_run_in_thread(finalize_put)
        self.disk_file.metadata = metadata


class DiskFile(object):
    """
    Manage object files on disk.

    :param path: path to devices on the node
    :param device: device name
    :param partition: partition on the device the object lives in
    :param account: account name for the object
    :param container: container name for the object
    :param obj: object name for the object
    :param keep_data_fp: if True, don't close the fp, otherwise close it
    :param disk_chunk_size: size of chunks on file reads
    :param bytes_per_sync: number of bytes between fdatasync calls
    :param iter_hook: called when __iter__ returns a chunk
    :param threadpool: thread pool in which to do blocking operations

    :raises DiskFileCollision: on md5 collision
    """

    def __init__(self, path, device, partition, account, container, obj,
                 logger, keep_data_fp=False, disk_chunk_size=65536,
                 bytes_per_sync=(512 * 1024 * 1024), iter_hook=None,
                 threadpool=None, obj_dir='objects', mount_check=False,
                 disallowed_metadata_keys=None):
        if mount_check and not check_mount(path, device):
            raise DiskFileDeviceUnavailable()
        self.disk_chunk_size = disk_chunk_size
        self.bytes_per_sync = bytes_per_sync
        self.iter_hook = iter_hook
        self.name = '/' + '/'.join((account, container, obj))
        name_hash = hash_path(account, container, obj)
        self.datadir = join(
            path, device, storage_directory(obj_dir, partition, name_hash))
        self.device_path = join(path, device)
        self.tmpdir = join(path, device, 'tmp')
        self.logger = logger
        self.disallowed_metadata_keys = disallowed_metadata_keys or []
        self.metadata = {}
        self.data_file = None
        self.fp = None
        self.iter_etag = None
        self.started_at_0 = False
        self.read_to_eof = False
        self.quarantined_dir = None
        self.keep_cache = False
        self.suppress_file_closing = False
        self.threadpool = threadpool or ThreadPool(nthreads=0)
        if not exists(self.datadir):
            return
        files = sorted(os.listdir(self.datadir), reverse=True)
        meta_file = None
        for afile in files:
            if afile.endswith('.ts'):
                self.data_file = None
                with open(join(self.datadir, afile)) as mfp:
                    self.metadata = read_metadata(mfp)
                self.metadata['deleted'] = True
                break
            if afile.endswith('.meta') and not meta_file:
                meta_file = join(self.datadir, afile)
            if afile.endswith('.data') and not self.data_file:
                self.data_file = join(self.datadir, afile)
                break
        if not self.data_file:
            return
        self.fp = open(self.data_file, 'rb')
        self.metadata = read_metadata(self.fp)
        if not keep_data_fp:
            self.close(verify_file=False)
        if meta_file:
            with open(meta_file) as mfp:
                for key in self.metadata.keys():
                    if key.lower() not in self.disallowed_metadata_keys:
                        del self.metadata[key]
                self.metadata.update(read_metadata(mfp))
        if 'name' in self.metadata:
            if self.metadata['name'] != self.name:
                self.logger.error(_('Client path %(client)s does not match '
                                    'path stored in object metadata %(meta)s'),
                                  {'client': self.name,
                                   'meta': self.metadata['name']})
                raise DiskFileCollision('Client path does not match path '
                                        'stored in object metadata')

    def __iter__(self):
        """Returns an iterator over the data file."""
        try:
            dropped_cache = 0
            read = 0
            self.started_at_0 = False
            self.read_to_eof = False
            if self.fp.tell() == 0:
                self.started_at_0 = True
                self.iter_etag = hashlib.md5()
            while True:
                chunk = self.threadpool.run_in_thread(
                    self.fp.read, self.disk_chunk_size)
                if chunk:
                    if self.iter_etag:
                        self.iter_etag.update(chunk)
                    read += len(chunk)
                    if read - dropped_cache > (1024 * 1024):
                        self._drop_cache(self.fp.fileno(), dropped_cache,
                                         read - dropped_cache)
                        dropped_cache = read
                    yield chunk
                    if self.iter_hook:
                        self.iter_hook()
                else:
                    self.read_to_eof = True
                    self._drop_cache(self.fp.fileno(), dropped_cache,
                                     read - dropped_cache)
                    break
        finally:
            if not self.suppress_file_closing:
                self.close()

    def app_iter_range(self, start, stop):
        """Returns an iterator over the data file for range (start, stop)"""
        if start or start == 0:
            self.fp.seek(start)
        if stop is not None:
            length = stop - start
        else:
            length = None
        try:
            for chunk in self:
                if length is not None:
                    length -= len(chunk)
                    if length < 0:
                        # Chop off the extra:
                        yield chunk[:length]
                        break
                yield chunk
        finally:
            if not self.suppress_file_closing:
                self.close()

    def app_iter_ranges(self, ranges, content_type, boundary, size):
        """Returns an iterator over the data file for a set of ranges"""
        if not ranges:
            yield ''
        else:
            try:
                self.suppress_file_closing = True
                for chunk in multi_range_iterator(
                        ranges, content_type, boundary, size,
                        self.app_iter_range):
                    yield chunk
            finally:
                self.suppress_file_closing = False
                self.close()

    def _handle_close_quarantine(self):
        """Check if file needs to be quarantined"""
        try:
            self.get_data_file_size()
        except DiskFileNotExist:
            return
        except DiskFileError:
            self.quarantine()
            return

        if self.iter_etag and self.started_at_0 and self.read_to_eof and \
                'ETag' in self.metadata and \
                self.iter_etag.hexdigest() != self.metadata.get('ETag'):
            self.quarantine()

    def close(self, verify_file=True):
        """
        Close the file. Will handle quarantining file if necessary.

        :param verify_file: Defaults to True. If false, will not check
                            file to see if it needs quarantining.
        """
        if self.fp:
            try:
                if verify_file:
                    self._handle_close_quarantine()
            except (Exception, Timeout), e:
                self.logger.error(_(
                    'ERROR DiskFile %(data_file)s in '
                    '%(data_dir)s close failure: %(exc)s : %(stack)'),
                    {'exc': e, 'stack': ''.join(traceback.format_stack()),
                     'data_file': self.data_file, 'data_dir': self.datadir})
            finally:
                self.fp.close()
                self.fp = None

    def is_deleted(self):
        """
        Check if the file is deleted.

        :returns: True if the file doesn't exist or has been flagged as
                  deleted.
        """
        return not self.data_file or 'deleted' in self.metadata

    def is_expired(self):
        """
        Check if the file is expired.

        :returns: True if the file has an X-Delete-At in the past
        """
        return ('X-Delete-At' in self.metadata and
                int(self.metadata['X-Delete-At']) <= time.time())

    @contextmanager
    def writer(self, size=None):
        """
        Context manager to write a file. We create a temporary file first, and
        then return a DiskWriter object to encapsulate the state.

        :param size: optional initial size of file to explicitly allocate on
                     disk
        :raises DiskFileNoSpace: if a size is specified and allocation fails
        """
        if not exists(self.tmpdir):
            mkdirs(self.tmpdir)
        fd, tmppath = mkstemp(dir=self.tmpdir)
        try:
            if size is not None and size > 0:
                try:
                    fallocate(fd, size)
                except OSError:
                    raise DiskFileNoSpace()
            yield DiskWriter(self, fd, tmppath, self.threadpool)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(tmppath)
            except OSError:
                pass

    def put_metadata(self, metadata, tombstone=False):
        """
        Short hand for putting metadata to .meta and .ts files.

        :param metadata: dictionary of metadata to be written
        :param tombstone: whether or not we are writing a tombstone
        """
        extension = '.ts' if tombstone else '.meta'
        with self.writer() as writer:
            writer.put(metadata, extension=extension)

    def unlinkold(self, timestamp):
        """
        Remove any older versions of the object file.  Any file that has an
        older timestamp than timestamp will be deleted.

        :param timestamp: timestamp to compare with each file
        """
        timestamp = normalize_timestamp(timestamp)

        def _unlinkold():
            for fname in os.listdir(self.datadir):
                if fname < timestamp:
                    try:
                        os.unlink(join(self.datadir, fname))
                    except OSError, err:    # pragma: no cover
                        if err.errno != errno.ENOENT:
                            raise
        self.threadpool.run_in_thread(_unlinkold)

    def _drop_cache(self, fd, offset, length):
        """Method for no-oping buffer cache drop method."""
        if not self.keep_cache:
            drop_buffer_cache(fd, offset, length)

    def quarantine(self):
        """
        In the case that a file is corrupted, move it to a quarantined
        area to allow replication to fix it.

        :returns: if quarantine is successful, path to quarantined
                  directory otherwise None
        """
        if not (self.is_deleted() or self.quarantined_dir):
            self.quarantined_dir = self.threadpool.run_in_thread(
                quarantine_renamer, self.device_path, self.data_file)
            self.logger.increment('quarantines')
            return self.quarantined_dir

    def get_data_file_size(self):
        """
        Returns the os.path.getsize for the file.  Raises an exception if this
        file does not match the Content-Length stored in the metadata. Or if
        self.data_file does not exist.

        :returns: file size as an int
        :raises DiskFileError: on file size mismatch.
        :raises DiskFileNotExist: on file not existing (including deleted)
        """
        try:
            file_size = 0
            if self.data_file:
                file_size = self.threadpool.run_in_thread(
                    getsize, self.data_file)
                if 'Content-Length' in self.metadata:
                    metadata_size = int(self.metadata['Content-Length'])
                    if file_size != metadata_size:
                        raise DiskFileError(
                            'Content-Length of %s does not match file size '
                            'of %s' % (metadata_size, file_size))
                return file_size
        except OSError, err:
            if err.errno != errno.ENOENT:
                raise
        raise DiskFileNotExist('Data File does not exist.')
