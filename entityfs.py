#!/usr/bin/env python3

import errno
#import fuse
import sys
import os
import datetime, time
import math
import stat
import base64;
import urllib.parse
import urllib.request, urllib.error, urllib.parse
import email.utils # not using email but this is where RFC2822 parser lives
import json
import traceback
import configparser
import ssl
import logging
from urllib.error import HTTPError
import pyfuse3
from pyfuse3 import FUSEError
import trio
from os import fsencode, fsdecode
from argparse import ArgumentParser

ALLOW_PASSWORD = False
ALLOW_TOKEN = True

DEFAULT_CONFIG={
    "chunk_size":str(1024*1024),
    "cache_limit":str(1024),
    "verify_https":"true"
};

LOG_FORMAT="%(levelname)s | %(asctime)s | %(message)s"

def log_exception():
    lines=traceback.format_exc().splitlines()
    for line in lines:
        logging.error(line)

class GHFSCache(object):
    """An LRU cache.
    If more than cache_limit chunks are stored, the oldest ones get dropped 
    (or cache_limit can be set to 0 for no limit).
    """
    def __init__(self,cache_limit):
        self.cache_limit=cache_limit
        self.ordered_keys=[]
        self.contents={}
    def get(self,file_id,chunk_number):
        key=(file_id,chunk_number)
        if key in self.contents:
            #print "getting from cache file {0} chunk {1}".format(file_id,chunk_number)
            #print "cache size: {0}".format(len(self.ordered_keys))
            try:
                position=self.ordered_keys.index(key)
                del self.ordered_keys[position]
            except ValueError as e:
                logging.debug("Cache key "+str(key)+" was found in cache contents, but not in LRU key list!");
                logging.debug("LRU key list was: "+str(self.ordered_keys));
                raise
            self.ordered_keys.append(key)
            return self.contents[key]
        else:
            return None;
    def put(self,file_id,chunk_number,contents):
        key=(file_id,chunk_number)
        if key in self.contents:
            self.remove_chunk(file_id,chunk_number)
        self.ordered_keys.append(key)
        self.contents[key]=contents
        #print "adding to cache file {0} chunk {1}".format(file_id,chunk_number)
        if self.cache_limit:
            num_to_delete=len(self.ordered_keys)-self.cache_limit;
            if num_to_delete>0:
                for i in range(num_to_delete):
                    del self.contents[self.ordered_keys[i]]
                logging.debug("Flushing cache elements: "+str(self.ordered_keys[0:num_to_delete]));
                del self.ordered_keys[0:num_to_delete]
    def remove_chunk(self,file_id,chunk_number):
        key=(file_id,chunk_number)
        try:
            position=self.ordered_keys.index(key)
            del self.ordered_keys[position]
        except ValueError as e:
            logging.debug("Cache key "+str(key)+" was found in cache contents, but not in LRU key list!");
            logging.debug("LRU key list was: "+str(self.ordered_keys));
            raise
        del self.contents[key]
    def remove_file(self,file_id):
        chunk_numbers=[k[1] for k in self.ordered_keys if k[0]==file_id]
        logging.debug("Uncaching file "+str(file_id)+" which had chunks "+str(chunk_numbers));
        for n in chunk_numbers:
            self.remove_chunk(file_id,n);

class GHFSConfigError(Exception):
    pass

class GHFSINode(object):
    def __init__(self,path,inode_number, parent_inode_number):
        self.path=path
        self.inode_number=inode_number
        self.parent_inode_number=parent_inode_number
        self.node_type="unvisited"
        self.open_file_handles=set()

# This class handles everything that doesn't care whether it's
# flat access or FilePathRule access, and shouldn't need too much
# cleanup to also be a base class for other path creation strategies.
# Derived classes need:
# get_file_length(self,path)->int,
# get_file_time(self,path)->float
# is_path_a_directory(self,path)->bool
# is_path_a_file(self,path)->bool
# get_entries_in_directory(self,path)->string[]
# workfile_id_of_path(self,path)->string
# and will probably use base class's openAPI(self,url) for API GET requests.
class BaseGHFS(pyfuse3.Operations):
    def __init__(self, config):
        super().__init__();

        self.auth = None

        if ALLOW_TOKEN and config.has_option("entityfs","api_token_secret"):
            conf_token = config.get("entityfs","api_token_secret")
            self.auth="Bearer "+conf_token;
        
        if (not self.auth and
            ALLOW_PASSWORD and
            config.has_option("entityfs","username") and
            config.has_option("entityfs","password")):

            if conf_username and conf_password:            
                userpass_str = "{0}:{1}".format(self.username,self.password);
                userpass_unencoded_bytes = bytes(userpass_str,"ascii");
                userpass_b64_bytes = base64.b64encode(userpass_unencoded_bytes);
                userpass_b64_ascii=userpass_b64_bytes.decode("ascii");
                self.auth="Basic "+userpass_b64_ascii;

        if not self.auth:
            print ("No credentials in config file")
            sys.exit(1)
                
        self.url=config.get("entityfs","url");
        self._chunk_size=config.getint("entityfs","chunk_size")
        self._cache_limit=config.getint("entityfs","cache_limit");
        verify_https_str=config.get("entityfs","verify_https")
        if verify_https_str.upper() in ["TRUE","YES","1"]:
            self.verify_https=True
        elif verify_https_str.upper() in ["FALSE","NO","0"]:
            logging.info("verify_https is off, invalid certificates will be accepted.");
            self.verify_https=False
        else:
            raise GHFSConfigError("verify_https is not a boolean");
        self._cache=GHFSCache(self._cache_limit);
        self._inodes={}
        
        self._open_file_handles={}
        self._next_file_handle=1;
        self._next_inode_number=pyfuse3.ROOT_INODE;
        self._make_inode("/", pyfuse3.ROOT_INODE);

    def _make_inode(self, path, parent_number):
        inode = GHFSINode(path, self._next_inode_number, parent_number);
        self._inodes[self._next_inode_number]=inode;
        self._next_inode_number+=1;        
        return inode
        
    # internal operations that talk to the server to provide the backing
    # for the public ones:
    def openAPI(self,relative_url,postbody=None):
        url=urllib.parse.urljoin(self.url,relative_url)
        logging.debug("Opening "+url);
        request=urllib.request.Request(url);
        request.add_header("Authorization",self.auth);
        try:
            if self.verify_https:
                if postbody:
                    request.add_header("Content-Type","application/json");
                    return urllib.request.urlopen(request,postbody);
                else:
                    return urllib.request.urlopen(request);
            else:
                ssl_context=ssl._create_unverified_context()
                return urllib.request.urlopen(request,context=ssl_context);
        except HTTPError as e:
            # this is normal if we just tried to get a file that doesn't exist
            logging.debug("HTTP error: "+str(e));
            try:
                logging.debug("Error response body: "+e.read().decode("utf8"))
                logging.debug(f"Attempted url was {url}");
            except Exception:
                pass;
            return None        
        except Exception:
            logging.error("Couldn't open {0}".format(url));
            log_exception()
            raise; 

    def _open_range(self,relative_url,size,offset):
        url=urllib.parse.urljoin(self.url,relative_url)
        request=urllib.request.Request(url);
        request.add_header("Authorization",self.auth);
        range_header="bytes={0}-{1}".format(offset,offset+size-1);
        request.add_header("Range",range_header);
        logging.debug("Opening "+url+" for range "+range_header);
        try:
            if self.verify_https:
                return urllib.request.urlopen(request);   
            else:
                ssl_context=ssl._create_unverified_context()
                return urllib.request.urlopen(request,context=ssl_context);
        except HTTPError as e:
            # this is normal if we just tried to get a file that doesn't exist
            logging.debug("HTTP error: "+str(e));
            return None
        except Exception:
            logging.error("Couldn't open {0}".format(url));
            log_exception()
            raise
        
    def _parse_datetime(self,dt):
        # strptime format string would be "%a %b %d %H:%M:%S %Z %Y" but
        # that depends on system strptime being aware of the right zone
        # email.utils has the RFC2822 parser that respects timezones
        # independently of system time zone
        return email.utils.mktime_tz(email.utils.parsedate_tz(dt));

    def _now(self):
        return time.mktime(datetime.datetime.now().timetuple());

    def _now_ns(self):
        return int(time.time()*1e9)
    
    # stuff we don't support because we are currently read-only and have
    # no hardlinks or extended attributes:
    # create
    # getxattr
    # link
    # listxattr
    # mkdir
    # mknod
    # readlink
    # removexattr
    # rename
    # rmdir
    # setattr
    # setxattr
    # symlink
    # unlink
    # write

    # no-ops because we have no mutable state to care about synchronizing:
    async def flush(self, fh):
        pass
    # forget already defaults to a no-op in the pyfuse3.Operations base class
    async def fsync(self, fh):
        pass
    async def fsyncdir(self, fh):
        pass    

    
    # lookup is super-important for pyfuse3! Other operations take inode
    # or file handle numbers, this is the only one that deals with path names
    # as a primary concern.
    # Assuming parent_inode is an inode we've already decided was a directory,
    # check if name is a name in that directory, and if so do getattr on it.
    async def lookup(self, parent_inode_number, name, ctx=None):
        parent_inode = self._visit_inode_or_error(parent_inode_number)        
        self._visit_inode(parent_inode);        
        if parent_inode.node_type!="directory":
            raise FUSEError(errno.ENOENT);
        if name == ".":
            return self._getattr(parent_inode.inode_number)
        if name=="..":
            return self._getattr(parent_inode.parent_inode_number);
        if name in parent_inode.children:
            return self._getattr(parent_inode.children[name])
        raise FUSEError(errno.ENOENT);

    # getattr is closely connected to lookup, since both are returning
    # the same EntryAttributes object
    async def getattr(self,inode_number, ctx=None):
        return self._getattr(inode_number);
    
    def _visit_inode(self,inode):
        if inode.node_type=="unvisited":
            if self.is_path_a_directory(inode.path):
                inode.node_type="directory"
                children=self.get_entries_in_directory(inode.path)
                inode.child_names=[]
                inode.children={}
                for name in children:
                    if inode.path[-1]=="/":
                        new_path = inode.path+name
                    else:
                        new_path = inode.path+"/"+name
                    # no need to recurse on the child's properties just yet;
                    # just assign an unvisited inode number so a later call
                    # will know which child it is
                    new_node = self._make_inode(new_path, inode.inode_number);
                    inode.child_names.append(name)
                    inode.children[name]=new_node.inode_number;
            elif self.is_path_a_file(inode.path):
                inode.node_type="file"
                inode.file_length=self.get_file_length(inode.path);
                inode.file_time=self.get_file_time(inode.path);
                inode.workfile_id=self.workfile_id_of_path(inode.path);
            else:
                inode.node_type="error"

    def _visit_inode_or_error(self,inode_number):
        if inode_number not in self._inodes:
            raise FUSEError(errno.ENOENT);
        inode = self._inodes[inode_number]
        self._visit_inode(inode);
        return inode;        
    
    def _getattr(self, inode_number):
        inode = self._visit_inode_or_error(inode_number)
        if inode.node_type=="directory":
            now_ns=self._now_ns();
            entry=pyfuse3.EntryAttributes()
            entry.st_ino=inode.inode_number
            entry.generation=0
            entry.entry_timeout=3600
            entry.attr_timeout=3600
            entry.st_mode=stat.S_IFDIR|0o500
            entry.st_nlink=1
            entry.st_uid=os.getuid()
            entry.st_gid=os.getgid()
            entry.st_rdev = 0
            entry.st_size = 0
            entry.st_blksize = self._chunk_size
            entry.st_blocks = 1
            entry.st_atime_ns = now_ns
            entry.st_mtime_ns = now_ns
            entry.st_ctime_ns = now_ns
            return entry
        if inode.node_type=="file":
            file_ns = int(inode.file_time*1e9)
            entry = pyfuse3.EntryAttributes()
            entry.st_ino=inode.inode_number
            entry.generation=0
            entry.entry_timeout=3600
            entry.attr_timeout=3600
            entry.st_mode=stat.S_IFREG|0o400
            entry.st_nlink=1
            entry.st_uid=os.getuid()
            entry.st_gid=os.getgid()
            entry.st_rdev = 0
            entry.st_size=inode.file_length
            # st_blksize is a hint to the OS for what block size it
            # "should" read
            entry.st_blksize = self._chunk_size
            # st_blocks is defined for 512-byte blocks, not related to
            # st_blksize
            entry.st_blocks=int(math.ceil(inode.file_length/512))
            entry.st_ctime_ns=file_ns
            entry.st_atime_ns=file_ns
            entry.st_mtime_ns=file_ns
            return entry            
        raise FUSEError(errno.ENOENT);

    # return true if the operation should be "permitted" from OS perspective
    # (r/x on dir, r on file)
    async def access(self, inode_number, mode, ctx=None):
        inode = self._visit_inode_or_error(inode_number)
        self._visit_inode(inode);
        if inode.node_type=="directory":
            if mode & os.W_OK:
                return False
            return True
        if inode.node_type=="file":
            if mode & os.W_OK:
                return False
            if mode & os.X_OK:
                return False
            return True
        return False

    # get a new handle number associated with a directory inode
    async def opendir(self, inode_number, ctx):
        inode = self._visit_inode_or_error(inode_number);
        if inode.node_type!="directory":
            raise FUSEError(errno.EACCES);            
        handle=self._next_file_handle
        self._next_file_handle+=1
        self._open_file_handles[handle]=inode_number;
        inode.open_file_handles.add(handle)
        return handle;

    # get a new handle number associated with a file inode,
    # return it in a FileInfo
    async def open(self, inode_number, flags, ctx):
        inode = self._visit_inode_or_error(inode_number);
        if inode.node_type!="file":
            raise FUSEError(errno.EACCES);            
        if flags & os.W_OK:
            raise FUSEError(errno.EACCES);            
        if flags & os.X_OK:
            raise FUSEError(errno.EACCES);
        handle=self._next_file_handle
        self._next_file_handle+=1
        self._open_file_handles[handle]=inode_number;
        inode.open_file_handles.add(handle)
        return pyfuse3.FileInfo(fh=handle, keep_cache=True)

    
    # get contents of directory, "returned" via readdir_reply callback system
    async def readdir(self,fh,offset, token):
        if fh not in self._open_file_handles:
            raise FUSEError(errno.ENOENT);
        inode_number = self._open_file_handles[fh];
        inode = self._visit_inode_or_error(inode_number)
        if inode.node_type != "directory":
            raise FUSEError(errno.EACCES);
        while offset<len(inode.child_names):
            name=inode.child_names[offset]
            attr=self._getattr(inode.children[name])
            keep_going = pyfuse3.readdir_reply(token,
                                               fsencode(name),
                                               attr,
                                               offset+1)
            if not keep_going:
                break
            offset = offset + 1


    # read a section of file
    async def read(self,fh, offset, size):
        # equivalent of:
        #  file.seek(offset)
        #  return file.read(size)
        # large reads might have requested a power of 2 well past the
        # actual EOF; restrain the size to actually fit in the file
        if fh not in self._open_file_handles:
            raise FUSEError(errno.ENOENT);
        path = self._inodes[self._open_file_handles[fh]].path;
        logging.debug("attempting read on "+path)
        try:
            if self.is_path_a_file(path):                
                length=self.get_file_length(path)
                if size+offset>length:            
                    size=length-offset;
                if size==0:
                    logging.debug("returning from read (zero-length)")
                    return b""
                logging.debug("read1")
                # three possible cases:
                # - requested range lies within one chunk which we
                #   don't have cached
                # - requested range lies within one chunk which we
                #   do have cached
                # - requested range lies across chunks
                chunk_of_first_byte=offset//self._chunk_size;
                chunk_of_last_byte=(offset+size-1)//self._chunk_size;
                if chunk_of_first_byte==chunk_of_last_byte:
                    logging.debug("returning from read (one chunk)")
                    return self._read_one_chunk(path,
                                                size,
                                                offset);
                            
                else:
                # spanning: get each necessary chunk, then join
                    slices=[]
                    for chunk_num in range(chunk_of_first_byte,chunk_of_last_byte+1):
                        slice_start=max(offset,chunk_num*self._chunk_size)
                        slice_end=min(offset+size,(1+chunk_num)*self._chunk_size)
                        slices.append(self._read_one_chunk(path,
                                                           slice_end-slice_start,
                                                           slice_start));
                    logging.debug("returning from read (spanning chunks)")
                    return b"".join(slices);
            elif self.is_path_a_directory(path):
                return b""
            else:
                return -errno.ENOENT;
        except:
            logging.error("File read error!");
            log_exception()

    def _read_one_chunk(self,path,size,offset):
        # just one chunk
        chunk_of_first_byte=offset//self._chunk_size;
        chunk=self._cache.get(path,chunk_of_first_byte);                        
        if not chunk:
            # if we don't have it yet...
            wfid=self.workfile_id_of_path(path);
            relative_url="v2/WorkFileContents/{0}".format(wfid)
            chunk=self._open_range(relative_url,
                                   self._chunk_size,
                                   self._chunk_size*chunk_of_first_byte).read();
            self._cache.put(path,chunk_of_first_byte,chunk)
        start=offset-(chunk_of_first_byte*self._chunk_size);
        return chunk[start:start+size];            

    # discard a file handle 
    async def release(self,fh):
        if fh in self._open_file_handles:
            inode=self._inodes[self._open_file_handles[fh]]
            del self._open_file_handles[fh];
            inode.open_file_handles.remove(fh);
            if len(inode.open_file_handles)==0:
                self._cache.remove_file(inode.path);

    # discard a file handle             
    async def releasedir(self,fh):
        if fh in self._open_file_handles:
            inode=self._inodes[self._open_file_handles[fh]]            
            del self._open_file_handles[fh];
            inode.open_file_handles.remove(fh);
            
class FlatGHFS(BaseGHFS):
    def __init__(self, config, *args, **kw):
        BaseGHFS.__init__(self, config, *args, **kw)
        self._file_properties={}
        
    def get_file_length(self,path):
        return self._look_up_file_properties(path)["length"]

    def get_file_time(self,path):
        return self._look_up_file_properties(path)["time"]

    def is_path_a_file(self,path):
        if self._look_up_file_properties(path):
            return True
        return False;

    def is_path_a_directory(self,path):
        return path=="/";

    def get_entries_in_directory(self,path):
        # only path this can be ever is "/"
        self._look_up_all_file_properties()
        return list(self._file_properties.keys());
    
    def _look_up_file_properties(self,fname):
        if fname[0]=="/":
            fname=fname[1:]        
        if fname in self._file_properties:
            return self._file_properties[fname];
        try:
            wfid=self.workfile_id_of_path(fname)
            url="v2/WorkFileProperties/{0}".format(wfid)            
            stream=self.openAPI(url)
            if not stream:
                logging.debug("Looked up properties for "+fname+
                              " at "+url+" and got back nothing")
                return None;
            f=stream.read().decode("utf8");
            j=json.loads(f);            
            received_name=self._file_json_object_to_fname(j);
            logging.debug("Looked up properties for "+fname+
                          " at "+url+" and got back a file which"+
                          " should be named "+received_name);
            if fname==received_name:            
                self._add_file_properties(j);
                return self._file_properties[fname];
            else:
                return None;
        except HTTPError as e:
            # this is normal if we just tried to get a file that doesn't exist
            logging.debug("HTTP error: "+str(e));
            return None
        except Exception as e:            
            log_exception()
            return None;        

    def workfile_id_of_path(self,fname):
        if fname[0]=="/":
            fname=fname[1:]
        dashAt=fname.rfind("-")
        if dashAt==-1:
            return fname
        else:
            return fname[dashAt+1:]
        
    def _file_json_object_to_fname(self,j):
        oName=j.get("originalName","")
        if oName:
            return "{0}-{1}".format(oName,j["id"])
        else:
            return "{0}".format(j["id"]);
        
    def _add_file_properties(self,j):
        try:
            fname=self._file_json_object_to_fname(j)
            self._file_properties[fname]={
                "time":self._parse_datetime(j["creationDatetime"]),
                "length":j["length"]
            }
        except Exception as e:
            log_exception()
            pass
        
    def _look_up_all_file_properties(self):
        f=self.openAPI("v2/WorkFileProperties").read().decode("utf8");
        js=json.loads(f);
        missing_keys=set(self._file_properties.keys());
        try:
            for j in js:
                self._add_file_properties(j);
                fname=self._file_json_object_to_fname(j)
                if fname in missing_keys:
                    missing_keys.remove(fname)
            for k in missing_keys:
                del self._file_properties[k];
        except Exception as e:
            log_exception()
            return;

# For now, this fetches a single static tree at mount time; assumption is
# you mount GHFS to do work on files that are already in the server and
# unmount it when you're done, so it doesn't need to track server-side
# changes. Tracking server-side changes gets semantically complex!
class RuleGHFS(BaseGHFS):
    def __init__(self, config, *args, **kw):
        BaseGHFS.__init__(self, config, *args, **kw)
        rulestring=config.get("entityfs","rules");
        if ((rulestring.startswith("[") and rulestring.endswith("]")) or
             (rulestring.startswith("{") and rulestring.endswith("}"))):
             self.fetch_tree_using_json(rulestring)
        else:
             self.fetch_tree_using_names(rulestring.split(","));

    def fetch_tree_using_names(self,requested_rule_names):        
        # get file path rules...
        url="v2/FilePathTree";
        first=True;
        for name in requested_rule_names:
            if first:
                url+="?rule="
                first=False;
            else:
                url+="&rule="
            url+=urllib.parse.quote(name);
        response=self.openAPI(url);
        if not response:
            print("Unable to read a tree (maybe bad credentials or bad rule name, see log)");
            sys.exit(1);
        treeTXT=response.read().decode("utf8");
        logging.debug("Starting up, got tree from server: "+treeTXT);
        self.tree=json.loads(treeTXT);

    def fetch_tree_using_json(self,body):        
        # get file path rules...
        url="v2/FilePathTree";
        if isinstance(body,str):
            body=body.encode("utf8");
        response = self.openAPI(url,body)
        if not response:
            print("Unable to read a tree (maybe bad credentials or bad rule name, see log)");
            sys.exit(1);
        treeTXT=response.read().decode("utf8");
        logging.debug("Starting up, got tree from server: "+treeTXT);
        self.tree=json.loads(treeTXT);

    def get_node_from_tree(self,path):
        parts=path.split("/");
        subtree=self.tree;
        for p in parts:
            if p!="":
                if "dir" in subtree and p in subtree["dir"]:
                    subtree=subtree["dir"][p]
                else:
                    return None
        return subtree;
                
    def get_file_length(self,path):
        node=self.get_node_from_tree(path)
        if node and "length" in node:
            return node["length"]

    def get_file_time(self,path):
        node=self.get_node_from_tree(path)
        if node and "creationDatetime" in node:
            return self._parse_datetime(node["creationDatetime"]);

    def is_path_a_file(self,path):
        node=self.get_node_from_tree(path)
        return node and "id" in node;

    def is_path_a_directory(self,path):
        node=self.get_node_from_tree(path)
        return node and "dir" in node;
    
    def get_entries_in_directory(self,path):
        node=self.get_node_from_tree(path)
        if node and "dir" in node:
            return list(node["dir"].keys());
        
    def workfile_id_of_path(self,path):
        node=self.get_node_from_tree(path)
        if node and "id" in node:
            return node["id"]

def parse_args():
    parser = ArgumentParser()
    parser.add_argument('--config', dest='config', type=str, default=None,
                        help=(
                            "Location of the entityfs config file "+
                            "(default is $ENTITYFS_CONFIG or ~/.entityfs"));
    parser.add_argument('mountpoint',type=str,
                        help='Where to mount the filesystem')
    parser.add_argument('-f', dest='foreground',
                        action="store_true",default=False,
                        help=(
                            "Ignored (accepted as an argument to"+
                            "accommodate a behavior of SingularityCE"));
    return parser.parse_args();

def main():
    #usage="""
    #ENTITYFS client. -s and -o auto_unmount are forced automatically.
    #""" + Fuse.fusage
    cmd_options = parse_args()    


    if cmd_options.config:
        config_path = cmd_options.config;
        if not os.path.isfile(config_path):
            print("Config file was specified at "+config_path+" but there is not a file by that name.", file=sys.stderr);
            return
    else:
        config_path=os.environ.get("ENTITYFS_CONFIG")
        if config_path:
            if not os.path.isfile(config_path):
                print("ENTITYFS_CONFIG is defined as "+config_path+" but there is not a file by that name.", file=sys.stderr);
                return
        else:
            config_path=os.path.join(os.path.expanduser("~"),".entityfs")
            if not os.path.isfile(config_path):
                print("There is no file named "+config_path+", you have not defined ENTITYFS_CONFIG to specify another config file, and you did not provide a --config argument.", file=sys.stderr);
                return
    config=configparser.ConfigParser(DEFAULT_CONFIG);
    config.read([config_path]);

    if config.has_option("entityfs","logfile"):
        if config.has_option("entityfs","loglevel"):
            levelname=config.get("entityfs","loglevel");
        else:
            levelname="INFO"
        log_filename=config.get("entityfs","logfile");
        if(os.getcwd() == '/'):
            # In case the logfile path in the config file is a relative path,
            # if we're being run from the root of the filesystem,
            # use the config file to resolve the relative path.
            # This is to accommodate the --fusemount option of SingularityCE.
            relative_to_here = os.path.split(config_path)[0];
            log_filename = os.path.join(relative_to_here,log_filename);
        logging.basicConfig(filename=log_filename,
                            level=levelname,
                            format=LOG_FORMAT);
        logging.info("Starting entityfs log.");
        
    try:
        if config.has_option("entityfs","rules"):
           operations=RuleGHFS(config);
        else:           
           operations=FlatGHFS(config);
    except configparser.NoOptionError as e:
        print("Error in "+config_path+": "+e.message);
        return;
    except GHFSConfigError as e:
        print("Error in "+config_path+": "+e.message);
        return;

    options=set(pyfuse3.default_options)
    options.add("auto_unmount")

    pyfuse3.init(operations, cmd_options.mountpoint, options);
    
    logging.debug("entering main")
    try:
        trio.run(pyfuse3.main)
    except:
        pyfuse3.close()
        raise
    logging.debug("leaving main")
                            
if __name__=="__main__":
    main()
