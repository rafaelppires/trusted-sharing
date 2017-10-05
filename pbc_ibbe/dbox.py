import os
import sys
import dropbox
import time
import concurrent
from concurrent.futures import ThreadPoolExecutor

class DropboxCloudCmd:

    token = 'BIHEAThi-nQAAAAAAAAAYSqX7tpWpHvnJ9sLl-rKKTesKkZXm7iwwLbIFHGalf99'
    client = dropbox.client.DropboxClient(token)
    dbx = dropbox.Dropbox(token)

    @staticmethod
    def clear():
        folder_metadata = DropboxCloudCmd.client.metadata('/')
        for f in folder_metadata['contents']:
            print('Deleting ', f['path'])
            DropboxCloudCmd.client.file_delete(f['path'])

    @staticmethod
    def get(k, dest_file):
        try :
            print('retreiving /' + k)
            # following method is throwing an exception?
            #f, metadata = DropboxCloudCmd.client.get_file_and_metadata('/' + k)
            DropboxCloudCmd.dbx.files_download_to_file(dest_file, '/' + k)            
            #print("META ", fm)          
            #print("CONTENT ", r)
            #return r.read()
        except dropbox.rest.ErrorResponse as err:
            print(str(err.body))
            print('FATAL ERRROR!!!!!!!!!!!!!!1')
            return None

    @staticmethod
    def put(k, v):
        print('uploading /' + k)
        DropboxCloudCmd.dbx.files_upload(v, '/' + k,
            mode=dropbox.files.WriteMode.overwrite)


    entries = []

    @staticmethod
    def put_in_session(k, v):
        r = DropboxCloudCmd.dbx.files_upload_session_start(v, True)        
        s_cursor = dropbox.files.UploadSessionCursor(session_id=r.session_id, offset=len(v))
        s_commit = dropbox.files.CommitInfo(path=k, mode=dropbox.files.WriteMode.overwrite)
        u = dropbox.files.UploadSessionFinishArg(cursor=s_cursor, commit=s_commit)
        DropboxCloudCmd.entries.append(u);

    
    @staticmethod
    def put_multiple(fname):

        DropboxCloudCmd.entries = []
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=128)
        futures = []
        
        with open(fname) as f:    
            for line in f:
                (k, f_item) = line.strip().split(',')
                print("uploading /", k)
                with open(f_item, 'rb') as content_file:
                    content = content_file.read()
                    futures.append(executor.submit(DropboxCloudCmd.put_in_session, "/" + k, content))

        concurrent.futures.wait(futures)
        batch = DropboxCloudCmd.dbx.files_upload_session_finish_batch(DropboxCloudCmd.entries)

    @staticmethod
    def download_multiple(fname):
        with open(fname) as f:
            for line in f:
                (cloud_file, local_file) = line.strip().split(',')
                DropboxCloudCmd.get(cloud_file, local_file)

if __name__ == "__main__":
    
    command = sys.argv[1]
    if (command == "clear"):
        DropboxCloudCmd.clear()
    else:
        key = sys.argv[2]
        file_value = sys.argv[3]
        
        if (command == "upload"):
            with open(file_value, 'rb') as content_file:
                content = content_file.read()
                DropboxCloudCmd.put(key, content)
        
        elif command == "download":
            DropboxCloudCmd.get(key, file_value)
                
        elif command == "put_multiple":
            content = DropboxCloudCmd.put_multiple(key)

        elif command == "download_multiple":
            DropboxCloudCmd.download_multiple(key)

