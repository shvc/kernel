# patch vfs->read to decrypt specified file

# platform
- Centos 7
- Centos 6

# usage
- make
- insmod
insmod with default filename: /tmp/test.txt
```insmod decrypt_file.ko```
insmod with specified filename:
```insmod decrypt_file.ko filename="/root/abc.c"```

#others
