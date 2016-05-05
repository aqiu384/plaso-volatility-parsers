# -*- coding: utf-8 -*-

import re

from plaso.containers import time_events
from plaso.lib import eventdata
from plaso.parsers import manager
from plaso.parsers import text_parser

TIMELINER_MODIFIED_EVENTS = [
  'IEHISTORY',
  'PROCESS',
  'LOADTIME',
  'THREAD',
  'SHIMCACHE'
]

TIMELINER_EVENTS = {
  'LIVE RESPONSE': re.compile(''),
  'IEHISTORY': re.compile(
    '(?P<imageFileName>.*)->(?P<url>.*) PID: (?P<uniquePid>.*)/Cache type \"'
    '(?P<signature>.*)\" at (?P<objOffset>.*)'
  ),
  'PROCESS': re.compile('(?P<imageFileName>.*) PID: (?P<pid>.*)/PPID: (?P<ppid>.*)/POffset: (?P<offset>.*)'),
  'PROCESS LastTrimTime': re.compile(
    '(?P<imageFileName>.*) PID: (?P<pid>.*)/PPID: '
    '(?P<ppid>.*)/POffset: (?P<offset>.*)'
  ),
  'Handle (Key)': re.compile('(?P<name>.*) PID: (?P<pid>.*)/PPID: (?P<ppid>.*)/POffset: (?P<offset>.*)'),
  'PE HEADER 32-bit (dll)': re.compile(
    '(?P<basename>.*) Process: (?P<imageFileName>.*) PID: '
    '(?P<pid>.*)/PPID: (?P<ppid>.*)/POffset: (?P<offset>.*)/DLL Base: (?P<dllBase>.*)'
  ),
  'PE HEADER (exe)': re.compile(
    '(?P<basename>.*) Process: (?P<imageFileName>.*) PID: '
    '(?P<pid>.*)/PPID: (?P<ppid>.*)/POffset: (?P<offset>.*)/DLL Base: (?P<dllBase>.*)'
  ),
  'PE HEADER (dll)': re.compile(
    '(?P<basename>.*) Process: (?P<imageFileName>.*) PID: '
    '(?P<pid>.*)/PPID: (?P<ppid>.*)/POffset: (?P<offset>.*)/DLL Base: (?P<dllBase>.*)'
  ),
  'PE HEADER DEBUG': re.compile(
    '(?P<basename>.*) Process: (?P<imageFileName>.*) PID: '
    '(?P<pid>.*)/PPID: (?P<ppid>.*)/POffset: (?P<offset>.*)/DLL Base: (?P<dllBase>.*)'
  ),
  'DLL LOADTIME (exe)': re.compile(
    '(?P<basename>.*) Process: (?P<imageFileName>.*) PID: '
    '(?P<pid>.*)/PPID: (?P<ppid>.*)/POffset: (?P<offset>.*)/DLL Base: (?P<dllBase>.*)'
  ),
  'DLL LOADTIME (dll)': re.compile(
    '(?P<basename>.*) Process: (?P<imageFileName>.*) PID: '
    '(?P<pid>.*)/PPID: (?P<ppid>.*)/POffset: (?P<offset>.*)/DLL Base: (?P<dllBase>.*)'
  ),
  'SOCKET': re.compile(
    'LocalIP: (?P<localIp>.*)/Protocol: (?P<protocol>.*)\((?P<protos>.*)\){0} PID: '
    '(?P<pid>.*)/POffset: (?P<offset>.*)'
  ),
  'EVT LOG': re.compile(
    '(?P<fields1>.*) (P<fields2>.*)/(P<fields3>.*)/(P<fields4>.*)/'
    '(P<fields5>.*)/(P<fields6>.*)/(P<fields7>.*)'
  ),
  'NETWORK CONNECTION': re.compile('(?P<conn>.*) (?P<pid>.*)/(?P<protocol>.*)/(?P<state>.*)/(?P<offset>.*)'),
  'THREAD': re.compile('(?P<image>.*) PID: (?P<pid>.*)/TID: (?P<tid>.*)'),
  'SYMLINK': re.compile(
    '(?P<name>.*)->(?P<linkTarget>.*) POffset: (?P<offset>.*)/Ptr: '
    '(?P<pointerCount>.*)/Hnd: (?P<handleCount>.*)'
  ),
  'PE HEADER (module)': re.compile('(?P<modName>.*) Base: (?P<modBase>.*)'),
  'USER ASSIST': re.compile(
    '(?P<subname>.*) Registry: (?P<reg>.*)/ID: (?P<id>.*)/Count: '
    '(?P<count>.*)/FocusCount: (?P<fc>.*)/TimeFocused: (?P<tf>.*)'
  ),
  'SHIMCACHE': re.compile('(?P<path>.*)'),
  '_HBASE_BLOCK TimeStamp': re.compile('(?P<offset>.*)'),
  '_CMHIVE LastWriteTime': re.compile('(?P<offset>.*)'),
  'REGISTRY': re.compile('(?P<item>.*) Registry: (?P<reg>.*)'),
  'TIMER': re.compile(
    '(?P<moduleName>.*) Signaled: (?P<signaled>.*)/Routine: '
    '(?P<routine>.*)/Period(ms): (?P<period>.*)/Offset: (?P<offset>.*)'
  )
}


class TimelinerEvent(time_events.PosixTimeEvent):
  DATA_TYPE = u'fs:mactime:line'

  def __init__(self, posix_time, usage, row_offset, filename):
    super(TimelinerEvent, self).__init__(posix_time, usage)
    self.offset = row_offset
    self.filename = filename


class TimelinerParser(text_parser.TextCSVParser):
  NAME = u'vol_timeliner'
  DESCRIPTION = u'Parser for Volatility\'s timeliner command output.'

  COLUMNS = [
      u'md5', u'name', u'inode', u'mode_as_string', u'uid', u'gid', u'size',
      u'atime', u'mtime', u'ctime', u'btime']
  VALUE_SEPARATOR = b'|'
  _TIMELINER_REGEX = re.compile('\[(?P<type>.*)\]')

  _TIMESTAMP_DESC_MAP = {
      u'atime': eventdata.EventTimestamp.ACCESS_TIME,
      u'btime': eventdata.EventTimestamp.CREATION_TIME
  }

  def _GetIntegerValue(self, row, value_name):
    value = row.get(value_name, None)
    try:
      return int(value, 10)
    except (TypeError, ValueError):
      return

  def VerifyRow(self, unused_parser_mediator, row):
      results = self._TIMELINER_REGEX.match(row.get(u'name', None))
      return results.group('type') in TIMELINER_EVENTS

  def ParseRow(self, parser_mediator, row_offset, row):
    filename = row.get(u'name', None)

    for value_name, timestamp_description in iter(self._TIMESTAMP_DESC_MAP.items()):
      posix_time = self._GetIntegerValue(row, value_name)
      if not posix_time:
        continue

      event_object = TimelinerEvent(posix_time, timestamp_description, row_offset, filename)
      parser_mediator.ProduceEvent(event_object)


manager.ParsersManager.RegisterParser(TimelinerParser)
