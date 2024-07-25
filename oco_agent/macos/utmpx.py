from ctypes import CDLL, Structure, POINTER, c_int64, c_int32, c_int16, c_char, c_uint32
from ctypes.util import find_library
import datetime, os, shlex

c = CDLL(find_library('System'))

# https://opensource.apple.com/source/Libc/Libc-1158.50.2/include/NetBSD/utmpx.h.auto.html

BOOT_TIME     =  2
USER_PROCESS  =  7
DEAD_PROCESS  =  8
SHUTDOWN_TIME = 11

class timeval(Structure):
    _fields_ = [
        ('tv_sec',  c_int64),
        ('tv_usec', c_int32),
    ]

class utmpx(Structure):
    _fields_ = [
        ('ut_user', c_char*256),
        ('ut_id',   c_char*4),
        ('ut_line', c_char*32),
        ('ut_pid',  c_int32),
        ('ut_type', c_int16),
        ('ut_tv',   timeval),
        ('ut_host', c_char*256),
        ('ut_pad',  c_uint32*16),
    ]

setutxent_wtmp = c.setutxent_wtmp
setutxent_wtmp.restype = None

getutxent_wtmp = c.getutxent_wtmp
getutxent_wtmp.restype = POINTER(utmpx)

endutxent_wtmp = c.setutxent_wtmp
endutxent_wtmp.restype = None

def parseUtmpx(dateObjectSince):
    # - initialize a session with setutxent_wtmp
    # - iterate through getutxent_wtmp until a NULL record, indicating no more
    # - finalize session with endutxent_wtmp

    users = []
    setutxent_wtmp(0)
    entry = getutxent_wtmp()
    while entry:
        e = entry.contents
        entry = getutxent_wtmp()
        if e.ut_type != USER_PROCESS: continue
        dateObject = datetime.datetime.fromtimestamp(e.ut_tv.tv_sec, tz=datetime.timezone.utc)
        if(dateObject <= dateObjectSince): continue
        #if e.ut_line != b"console": continue  # GUI logins only
        users.append({
            'display_name': os.popen('id -F '+shlex.quote(e.ut_user.decode('utf-8'))).read().strip(),
            'username': e.ut_user.decode('utf-8'),
            'console': e.ut_line.decode('utf-8'),
            'timestamp': dateObject.strftime('%Y-%m-%d %H:%M:%S')
        })
    endutxent_wtmp()
    return users
