# PROJ_Q_YV35_Host_Update_Tool
Firware update from host by Freeipmi(ipmi-raw).

## REQUIREMENT
- OS: Linux
- CMAKE: 3.12

## FEATURE
- Muti-process circumstance prevent is supported
- Countermeasure of interrupt while exe running is supported

## BUILD
```
cmake -G "Unix Makefiles"
make
```
- output exe file: ./output/host_update

## USAGE
#### Step1. Move exe file to host
#### Step2. Run exe file
- Command: **./host_update <fw_type> <img_path> <log_level>**
  - *fw_type*: Firmware type\
               [**0**]BIC [**1**]BIOS [**2**]CPLD
  - *img_path*: Image path
  - *log_level*: (optional) Log level\
               [**-v**]L1 [**-vv**]L2 [**-vvv**]L3

## NOTE
- BIOS/CPLD update havn't support yet.
