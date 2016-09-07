# decrypt specified file
- hook vfs function:

	file->f_inode->i_fop->read

# platform
- Centos 7
- Centos 6

# usage
- make
- insmod
	insmod with default filename: /tmp/test.txt

	`insmod decrypt_file.ko`

	insmod with specified filename: /root/abc.c

	`insmod decrypt_file.ko filename="/root/abc.c"`

- test the default file

	```
	cat /tmp/test.txt
	abABCc
	
	head /tmp/test.txt
	ABabcC
	
	```

#others
- 目前仅实现了文件内容大小写转换功能
- 目前信任进程名硬编码为： head

