# -*- coding: utf-8 -*-

import re

from plaso.containers import time_events
from plaso.lib import eventdata
from plaso.parsers import manager
from plaso.parsers import text_parser

MFTPARSER_EVENTS = {
  'MFT FILE_NAME': re.compile('(?P<path>.*)\(Offset: (?P<offset>.*)\)'),
  'MFT STANDARD_INFORMATION': re.compile('(?P<path>.*)\(Offset: (?P<offset>.*)\)')
}


class MftparserEvent(time_events.PosixTimeEvent):
  DATA_TYPE = u'fs:mactime:line'

  def __init__(self, posix_time, usage, row_offset, filename, inode_number, mode):
    super(MftparserEvent, self).__init__(posix_time, usage)
    self.inode = inode_number
    self.mode_as_string = mode
    self.offset = row_offset
    self.filename = filename


class MftparserParser(text_parser.TextCSVParser):
  NAME = u'vol_mftparser'
  DESCRIPTION = u'Parser for Volatility\'s mftparser command output.'

  COLUMNS = [
      u'md5', u'name', u'inode', u'mode_as_string', u'uid', u'gid', u'size',
      u'atime', u'mtime', u'ctime', u'btime']
  VALUE_SEPARATOR = b'|'
  _MFTPARSER_REGEX = re.compile('\[(?P<type>.*)\]')

  _TIMESTAMP_DESC_MAP = {
      u'atime': eventdata.EventTimestamp.ACCESS_TIME,
      u'btime': eventdata.EventTimestamp.CREATION_TIME,
      u'ctime': eventdata.EventTimestamp.CHANGE_TIME,
      u'mtime': eventdata.EventTimestamp.MODIFICATION_TIME,
  }

  def _GetIntegerValue(self, row, value_name):
    value = row.get(value_name, None)
    try:
      return int(value, 10)
    except (TypeError, ValueError):
      return

  def VerifyRow(self, unused_parser_mediator, row):
    results = self._MFTPARSER_REGEX.match(row.get(u'name', None))
    return results.group('type') in MFTPARSER_EVENTS

  def ParseRow(self, parser_mediator, row_offset, row):
    filename = row.get(u'name', None)
    mode = row.get(u'mode_as_string', None)

    inode_number = row.get(u'inode', None)
    if u'-' in inode_number:
      inode_number, _, _ = inode_number.partition(u'-')

    try:
      inode_number = int(inode_number, 10)
    except (TypeError, ValueError):
      inode_number = None

    for value_name, timestamp_description in iter(
        self._TIMESTAMP_DESC_MAP.items()):
      posix_time = self._GetIntegerValue(row, value_name)
      if not posix_time:
        continue

      event_object = MftparserEvent(posix_time, timestamp_description, row_offset, filename, inode_number, mode)
      parser_mediator.ProduceEvent(event_object)


manager.ParsersManager.RegisterParser(MftparserParser)
