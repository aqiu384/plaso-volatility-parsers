# -*- coding: utf-8 -*-

import re

from plaso.containers import time_events
from plaso.lib import eventdata
from plaso.parsers import manager
from plaso.parsers import text_parser

SHELLBAGES_EVENTS = {
  'SHELLBAGS ITEMPOS': re.compile('Name: (?P<name>.*)/Attrs: (?P<attrs1>.*)/(?P<attrs2>.*)'),
  'SHELLBAGS FILE_ENTRY': re.compile('Name: (?P<name>.*)/Attrs: (?P<attrs1>.*)/(?P<attrs2>.*)')
}


class ShellbagsEvent(time_events.PosixTimeEvent):
  DATA_TYPE = u'fs:mactime:line'

  def __init__(self, posix_time, usage, row_offset, filename):

    super(ShellbagsEvent, self).__init__(posix_time, usage)
    self.filename = filename
    self.offset = row_offset


class ShellbagsParser(text_parser.TextCSVParser):
  NAME = u'vol_shellbags'
  DESCRIPTION = u'Parser for Volatility\'s shellbags command output.'

  COLUMNS = [
      u'md5', u'name', u'inode', u'mode_as_string', u'uid', u'gid', u'size',
      u'atime', u'mtime', u'ctime', u'btime']
  VALUE_SEPARATOR = b'|'
  _SHELLBAGS_REGEX = re.compile('\[(?P<type>.*)\]')

  _TIMESTAMP_DESC_MAP = {
      u'atime': eventdata.EventTimestamp.ACCESS_TIME,
      u'btime': eventdata.EventTimestamp.CREATION_TIME,
      u'ctime': eventdata.EventTimestamp.CHANGE_TIME,
  }

  def _GetIntegerValue(self, row, value_name):
    value = row.get(value_name, None)
    try:
      return int(value, 10)
    except (TypeError, ValueError):
      return

  def VerifyRow(self, unused_parser_mediator, row):
    results = self._SHELLBAGS_REGEX.match(row.get(u'name', None))
    return results.group('type') in SHELLBAGES_EVENTS

  def ParseRow(self, parser_mediator, row_offset, row):
    filename = row.get(u'name', None)

    for value_name, timestamp_description in iter(self._TIMESTAMP_DESC_MAP.items()):
      posix_time = self._GetIntegerValue(row, value_name)
      if not posix_time:
        continue

      event_object = ShellbagsEvent(posix_time, timestamp_description, row_offset, filename)
      parser_mediator.ProduceEvent(event_object)


manager.ParsersManager.RegisterParser(ShellbagsParser)
