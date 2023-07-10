import cast.analysers.ua
from cast.analysers import log, CustomObject, create_link, Bookmark, external_link
import os
import sys
import traceback
import cast
from collections import OrderedDict
import random
from pathlib import Path
import re
#from _collections import defaultdict
import binascii


class UKNExtension(cast.analysers.ua.Extension):

    def __init__(self):        
        self.extensions = ['.ukn']
        self.active = False
        self.nbpgmCreated = 0

    def start_analysis(self):
        log.info(" Running extension code at the start of the analysis")
        try:
            options = cast.analysers.get_ua_options() #@UndefinedVariable
            if 'UKN' not in options:
                self.active = False
            else:
                self.active = True
        except Exception as e:
            exception_type, value, tb = sys.exc_info()
            log.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            #log.warning(traceback_str)

    @staticmethod
    def __create_object(self, name, typ, parent,filepath, bookmark=None):
        obj = None

        fullname = self.create_guid(typ, name) + '/' + filepath + '/'
        
        try:
            if name != "":
                obj = CustomObject()                    
                obj.set_name(name)
                obj.set_fullname(name)
                obj.set_type(typ)
                obj.set_parent(parent)
                obj.set_guid(fullname)
                
                obj.save()
                log.info('Saved object: ' + str(name) + ' type:' + str(typ))
                #log.info("bookmark is " + str(bookmark))
                
                if bookmark != None:    
                    obj.save_position(bookmark)

            return obj
        except Exception as e:
            log.warning('Exception while saving object ' + str(name) + ' error: ' + str(e))
            exception_type, value, tb = sys.exc_info()
            log.warning('exception_type = ' + str(exception_type) + ' Error message = ' + str(e))
            traceback_str = ''.join(traceback.format_tb(tb))
            log.warning(traceback_str)
            
        return None
    

    def start_file(self,file):  
        log.info("Running code at the Startfile")
        ## test mode only
        #self.active = True
        
        if not self.active:
            return # no need to do anything
        
        filepath = file.get_path().lower()
        #_, <- because we're discarding the first part of the splitext
        _, ext = os.path.splitext(filepath)
        
        #log.info("ext is" + str(ext))
        #log.info("file is " + str(file))
        
        if ext.lower() in self.extensions:
            self.filepath = file.get_path()
    
            log.info("Parsing UKN file %s..." % file)
            self.project = file.get_project()
            
            self.guid_data = Path(file.get_path()).name
    
            self.file = file
            filepath = file.get_path()

            #initialization
            self.lineNb = 0
            
            """
            Scan one UKN file
            """   
            content = ""
    
            with open_source_file(file.get_path()) as srcfile1:
                content = srcfile1.read()
    
            with open_source_file(file.get_path()) as srcfile1:
                #log.info("srcfile1" + str(srcfile1))             
                mylist = [line.rstrip('\n') for line in srcfile1]
                firstline = mylist[0]
                self.firstlineNb = 1
                self.lastlineNb = len(mylist)
                obj_name = self.guid_data.split(".")[0]
                self.start_pos = 1
                self.last_pos = 1
                #log.info("self.file is " + str(self.file))
                obj_bookmark = Bookmark(self.file, 0, -1, (self.lastlineNb-1), -1)
                #log.info("obj_bookmark is-->" + str(obj_bookmark))
                
                self.obj = self.__create_object(self,obj_name, "UKNProgram", self.file, self.filepath, obj_bookmark)
                self.nbpgmCreated += 1
                
            crc = binascii.crc32(content.encode()) 
            self.obj.save_property('checksum.CodeOnlyChecksum', crc % 2147483648)    
                                    


    def end_analysis(self):
        if not self.active:
            return
        log.info(" Statistics for AIA ")
        log.info("*****************************************************************")
        log.info(" Total UKN Program Objects Created  -- > " + str(self.nbpgmCreated))
        log.info("*****************************************************************")

    def create_guid(self, objectType, objectName):
        
        if not type(objectName) is str:
            return objectType + '/' + objectName.name
        else:
            return objectType + '/' + objectName
                    

def open_source_file(path, encoding=None):
    """
    Equivalent of python open(path) that autotdetects encoding.
    
    handles long path, UNC paths
    
    :param encoding: specified encoding (optional) 
    
    :rtype: file 
    """
    from chardet.universaldetector import UniversalDetector
    
    # for long pathes : see https://stackoverflow.com/questions/29557760/long-paths-in-python-on-windows
    local_path = path
    
    
    log.debug("sys.platform.startswith is " + str(sys.platform))

    if sys.platform.startswith('win32'):
        constant = '\\\\?\\'
        
        if not local_path.startswith(constant):
            local_path = local_path.replace('/', '\\')
            if local_path.startswith(r'\\'):
                local_path = r'\\?\UNC' + local_path[1:]
            elif os.path.isabs(local_path):
                local_path = constant + local_path
    
    log.debug("encoding is " + str(encoding))

    if not encoding:
        detector = UniversalDetector()
        with open(local_path, 'rb') as f:
            count = 0
            for line in f:
                detector.feed(line)
                count += 1
                if detector.done or count > 100: 
                    break
        detector.close()
    
        encoding = detector.result['encoding']
        log.debug('File %s has %s as detected encoding' % (path, encoding))
        
    result = open(local_path, 'r', encoding=encoding, errors='replace')
    return result


