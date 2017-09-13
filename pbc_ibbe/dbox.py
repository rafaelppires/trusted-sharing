import sys
import dropbox

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
    def get(k):
        try :
            f, metadata = DropboxCloudCmd.client.get_file_and_metadata('/' + k)
            return f.read()
        except dropbox.rest.ErrorResponse:
            return None

    @staticmethod
    def put(k, v):
        DropboxCloudCmd.dbx.files_upload(v, '/' + k,
            mode=dropbox.files.WriteMode.overwrite)

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
            content = DropboxCloudCmd.get(key)
            with open(file_value, 'wb') as content_file:
                content_file.write(content)