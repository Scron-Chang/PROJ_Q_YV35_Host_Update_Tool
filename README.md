# PROJ_Q_YV35_Host_Update_Tool
Fw update from host by ipmi_raw tool

How to build:
    gcc -o host-fw-update-tool src/main.c lib/libfreeipmi.a


## BUILD by CMAKE
```
cmake -G "Unix Makefiles"
make
```
output execute file: ./output/host_update
