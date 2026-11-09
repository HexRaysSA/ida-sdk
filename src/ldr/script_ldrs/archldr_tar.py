# Sample archive loader: TAR file format
# Feel free to improve it, this is just a sample

import os
import os.path
import tarfile
import shutil
import tempfile
import idaapi
from ida_kernwin import Choose


# -----------------------------------------------------------------------
def accept_file(li, filename):
    """
    Check input file format.
    This function will be called one or more times depending on the result value.

    @param li: a file-like object which can be used to access the input data
    @param filename: name of the file, if it is an archive member name then the actual file doesn't exist
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary {
                'format': "name",
                'options': integer,
                'flags': integer
                }
                options: should be 1,
                         if ORed with ACCEPT_ARCHIVE then it is an archive loader
                         if ORed with ACCEPT_CONTINUE then this function will be called another time
                         if ORed with ACCEPT_FIRST then indicates preferred format
                loader_flags: see GENFLG_
    """
    li.seek(0)
    try:
        t = tarfile.open(fileobj=li, mode='r|*')
        t.close()
        (_, ext) = os.path.splitext(filename)
        if ext not in (".tar", ".tgz", "tar.gz"):
            return 0
        return {'format': "TAR archive",
                'options': 1 | idaapi.ACCEPT_ARCHIVE}
    except Exception:
        pass
    return 0


# -----------------------------------------------------------------------
def _read_whole_file(li):
    li.seek(0)
    return li.read()


# -----------------------------------------------------------------------
def _tmpnam():
    (h, n) = tempfile.mkstemp()
    os.close(h)
    return n


# -----------------------------------------------------------------------
class TarMemberChoose(Choose):
    """
    TAR archive members selection chooser
    """

    def __init__(self, archive, items):
        title = "Archive: " + archive
        Choose.__init__(
            self,
            title,
            [["File name", Choose.CHCOL_PATH | 60],
             ["Size",      Choose.CHCOL_DEC  | 10]],
            icon=-1, y1=-2,
            flags = Choose.CH_MODAL)
        self.items = items

    def OnGetLine(self, n):
        return [self.items[n].name, str(self.items[n].size)]

    def OnGetSize(self):
        return len(self.items)


# -----------------------------------------------------------------------
def process_archive(li, archive, defmember, neflags, formatname):
    """
    Display list of archive members and let the user select one.
    Extract the selected archive member into a temporary file.

    @param li:         a file-like object which can be used to access the input data
    @param archive:    name of archive
    @param defmember:  extract the specified member
    @param neflags:    options selected by the user, see loader.hpp
    @param formatname: name of type of the file

    @return: ''     cancelled by the user
             string error message
             dictionary {
                'temp_file': string,
                'module_name': string,
                'neflags': integer
                }
                temp_file: name of the file with the extracted archive member
                module_name: name of the extracted archive member
                neflags: options selected by the user, see loader.hpp
    """
    li.seek(0)
    try:
        t = tarfile.open(fileobj=li, mode='r|*')
    except tarfile.TarError as e:
        return str(e)

    # list of archive members,
    members = t.getmembers()
    t.close()

    # we are interested in regular files only
    items = [m for m in members if m.type==tarfile.REGTYPE ]

    # if default archive member is specified
    if defmember:
        for m in items:
            if os.path.basename(m.name) == defmember:
                selected_item = m
                break
        else:
            return "Unknown TAR archive default member: %s" % defmember
    else:
        chooser = TarMemberChoose(archive, items)
        code = chooser.Show(True)
        if code == Choose.NO_SELECTION:
            return ""       # user canceled
        selected_item = items[code]

    # construct archive member name
    member_name = os.path.basename(selected_item.name)
    module_name = os.path.join(os.path.dirname(archive), member_name)

    # file for archive member
    workfile = _tmpnam()

    # extract member
    # there is a bug reported in 2010 year but not fixed yet:
    # http://bugs.python.org/issue10436
    li.seek(0)
    buf = _read_whole_file(li)
    (h, workfile_tar) = tempfile.mkstemp()
    os.write(h, buf)
    os.close(h)

    t = tarfile.open(name=workfile_tar, mode='r:*')
    tarinfo = t.getmember(selected_item.name)
    f_in = t.extractfile(tarinfo)
    f_out = open(workfile, 'wb')
    shutil.copyfileobj(f_in, f_out)
    f_out.close()
    f_in.close()
    t.close()
    os.unlink(workfile_tar)

    return {'temp_file': workfile, 'module_name': module_name}
