from Crypto.Hash import SHA1

from alive_progress import alive_bar

from os import SEEK_END

def get_file_size(handler):
    handler.seek(0, SEEK_END)
    file_size = handler.tell()
    handler.seek(0)
    return file_size

# TODO - Use Cuda to run calculations on the GPU instead of the CPU.
#pylint:disable=not-callable
def calculate_file_hash(handler):
    file_size = get_file_size(handler)
    hash_obj = SHA1.new()
    with alive_bar(file_size, title='calculating SHA1 file hash...') as bar:
        while(data := handler.read(8192)):
            hash_obj.update(data)
            bar(len(data))
    
    handler.seek(0) # reset the file pointer
    return hash_obj.hexdigest()