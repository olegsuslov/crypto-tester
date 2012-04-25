call "C:\Program Files\Microsoft Visual Studio 10.0\VC\vcvarsall.bat"
cl /I"..\include" /nologo /MT /O2 /c xyzcsp.c
rc /I"..\include" xyzcsp.rc
link /SUBSYSTEM:WINDOWS",5.0" /NODEFAULTLIB /DLL /DEF:xyzcsp.def /MACHINE:x86 /OUT:xyzcsp.dll xyzcsp.obj openssl.lib msvcrt.lib advapi32.lib kernel32.lib user32.lib gdi32.lib xyzcsp.res
copy xyzcsp.dll ..\testcsp\
rem copy xyzcsp.dll c:\windows\system32
del xyzcsp.res
del xyzcsp.obj
del xyzcsp.lib
del xyzcsp.exp
