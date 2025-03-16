# this is the sample progeam for detection code injection by security product

#### build
```bash
go mod init code_inject
go mod tidy
go build
```
#### execute
```bash
.\code_inject.exe <pid>

.\code_inject.exe 1234
```

![image](https://github.com/user-attachments/assets/d864c372-bc55-4366-aed5-ee02f8effa83)

```
.\wine code_inject.exe 280
Shell spawned successfully in process 280
```

