
format PE GUI 4.0

entry start

FONT_SIZE = 8

STRING_LENGTH = 255
SIZE_OF_EXECUTABLE_FILE = 44032
DOMAINS_FILE_POINTER = 23808

CAPTION_POINTER = 17414
CAPTION_LENGTH = 8

SUBCAPTION_POINTER = 17432
SUBCAPTION_LENGTH = 57

MAINMESSAGE_POINTER = 17548
MAINMESSAGE_LENGTH = 544

SECCAPTION_POINTER = 18638
SECCAPTION_LENGTH = 32

SECMESSAGE_POINTER = 18812
SECMESSAGE_LENGTH = 437

include 'win32a.inc'

section '.text' code readable executable

  start:
	invoke	GetCommandLine
	mov	esi,eax
    .find_path:
	lodsb
	cmp	al,20h
	je	.find_path
	cmp	al,22h
	je	.skip_quoted_path
	cmp	al,0Dh
	je	.path_end
	or	al,al
	jnz	.skip_path
	dec	esi
	jmp	.path_end
    .skip_path:
	lodsb
	cmp	al,20h
	je	.path_end
	cmp	al,0Dh
	je	.path_end
	or	al,al
	jnz	.skip_path
	dec	esi
	jmp	.path_end
    .skip_quoted_path:
	lodsb
	cmp	al,22h
	je	.path_end
	cmp	al,0Dh
	je	.path_end
	or	al,al
	jnz	.skip_quoted_path
	dec	esi
    .path_end:
	mov	[arguments],esi
	invoke	GetModuleHandle,0
	mov	[hinstance],eax
	invoke	DialogBoxParam,eax,IDD_MAIN,HWND_DESKTOP,DialogProc,0
	invoke	ExitProcess,0

  proc DialogProc uses ebx esi edi,hwnddlg,msg,wparam,lparam
	cmp	[msg],WM_INITDIALOG
	je	.wminitdialog
	cmp	[msg],WM_COMMAND
	je	.wmcommand
	cmp	[msg],WM_DROPFILES
	je	.wmdropfiles
	cmp	[msg],WM_CLOSE
	je	.wmclose
	xor	eax,eax
	jmp	.finish
    .wminitdialog:
	mov	eax,[hwnddlg]
	mov	[hwnddlg_main],eax
	invoke	LoadIcon,[hinstance],IDI_MAIN
	invoke	SendMessage,[hwnddlg],WM_SETICON,TRUE,eax
	invoke	SetWindowText,[hwnddlg],_program_title
	invoke	GetDlgItem,[hwnddlg],ID_PATCHFILE
	invoke	EnableWindow,eax,FALSE
	invoke	SendDlgItemMessage,[hwnddlg_main],IDC_DOMAIN1,EM_SETLIMITTEXT,STRING_LENGTH,0
	invoke	SendDlgItemMessage,[hwnddlg_main],IDC_DOMAIN2,EM_SETLIMITTEXT,STRING_LENGTH,0
	invoke	SendDlgItemMessage,[hwnddlg_main],IDC_DOMAIN3,EM_SETLIMITTEXT,STRING_LENGTH,0
	invoke	SendDlgItemMessageW,[hwnddlg_main],IDC_CAPTION,EM_SETLIMITTEXT,CAPTION_LENGTH,0
	invoke	SendDlgItemMessageW,[hwnddlg_main],IDC_SUBCAPTION,EM_SETLIMITTEXT,SUBCAPTION_LENGTH,0
	invoke	SendDlgItemMessageW,[hwnddlg_main],IDC_MAINMESSAGE,EM_SETLIMITTEXT,MAINMESSAGE_LENGTH,0
	invoke	SendDlgItemMessageW,[hwnddlg_main],IDC_SECCAPTION,EM_SETLIMITTEXT,SECCAPTION_LENGTH,0
	invoke	SendDlgItemMessageW,[hwnddlg_main],IDC_SECMESSAGE,EM_SETLIMITTEXT,SECMESSAGE_LENGTH,0
	invoke	DragAcceptFiles,[hwnddlg],TRUE
	mov	[ofn.lStructSize],sizeof.OPENFILENAME
	mov	eax,[hinstance]
	mov	[ofn.hInstance],eax
	mov	[ofn.lpstrCustomFilter],NULL
	mov	[ofn.lpstrFile],path_buffer
	mov	[ofn.nMaxFile],4000h
	mov	[ofn.lpstrFileTitle],name_buffer
	mov	[ofn.nMaxFileTitle],1000h
	mov	[ofn.lpstrInitialDir],NULL
	mov	[ofn.lpstrTitle],NULL
	mov	[ofn.Flags],OFN_EXPLORER + OFN_FILEMUSTEXIST + OFN_HIDEREADONLY
	mov	[ofn.nFileOffset],NULL
	mov	[ofn.lpstrDefExt],NULL
	mov	esi,[arguments]
	mov	edi,path_buffer
    .find_path:
	lodsb
	cmp	al,20h
	je	.find_path
	cmp	al,22h
	je	.copy_quoted_path
	cmp	al,0Dh
	je	.processed
	or	al,al
	jz	.processed
    .copy_path:
	stosb
	lodsb
	cmp	al,20h
	je	.path_end
	cmp	al,0Dh
	je	.path_end
	or	al,al
	jnz	.copy_path
	jmp	.path_end
    .copy_quoted_path:
	lodsb
	cmp	al,22h
	je	.quoted_path_end
	cmp	al,0Dh
	je	.quoted_path_end
	or	al,al
	jz	.quoted_path_end
	stosb
	jmp	.copy_quoted_path
    .path_end:
	dec	esi
    .quoted_path_end:
	xor	al,al
	stosb
	invoke	GetFullPathName,path_buffer,4000h,path_buffer,param_buffer
	invoke	GetFileAttributes,path_buffer
	test	eax,FILE_ATTRIBUTE_DIRECTORY
	jnz	.processed
	invoke	lstrcpy,name_buffer,dword [param_buffer]
	call	load_file
	jmp	.processed
    .wmcommand:
	cmp	[wparam],BN_CLICKED shl 16 + IDCANCEL
	je	.wmclose
	cmp	[wparam],BN_CLICKED shl 16 + ID_PATCHFILE
	je	.patch_file
	cmp	[wparam],BN_CLICKED shl 16 + ID_OPENFILE
	jne	.processed
    .open_file:
	mov	[ofn.nFilterIndex],1
	mov	[ofn.lpstrFilter],filter
	invoke	GetOpenFileName,ofn
	or	eax,eax
	jz	.processed
	call	load_file
	jmp	.processed
    .patch_file:
	call	patch_file
	jmp	.processed
    .wmdropfiles:
	invoke	DragQueryFile,[wparam],0,path_buffer,4000h
	invoke	DragFinish,[wparam]
	invoke	GetFileAttributes,path_buffer
	test	eax,FILE_ATTRIBUTE_DIRECTORY
	jnz	.drop_error
	invoke	GetFileTitle,path_buffer,name_buffer,1000h
	call	load_file
	jmp	.processed
    .drop_error:
	invoke	MessageBox,[hwnddlg],_drop_error,_program_title,MB_OK + MB_ICONEXCLAMATION
	jmp	.processed
    .wmclose:
	cmp	[hmemory],0
	je	.close
	invoke	VirtualFree,[hmemory],0,MEM_RELEASE
    .close:
	invoke	EndDialog,[hwnddlg],0
    .processed:
	mov	eax,TRUE
    .finish:
	ret
  endp

  proc load_file uses ebx esi edi
	invoke	CreateFile,path_buffer,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	cmp	eax,INVALID_HANDLE_VALUE
	je	.open_error
	mov	[hfile],eax
	invoke	GetFileSize,eax,0
	cmp	eax,SIZE_OF_EXECUTABLE_FILE
	jne	.invalid_file
	invoke	VirtualAlloc,0,eax,MEM_COMMIT,PAGE_READWRITE
	or	eax,eax
	jz	.memory_error
	mov	ebx,eax
	invoke	ReadFile,[hfile],eax,SIZE_OF_EXECUTABLE_FILE,bytes_count,0
	or	eax,eax
	jz	.read_error
	cmp	[bytes_count],SIZE_OF_EXECUTABLE_FILE
	jne	.read_error
	invoke	CloseHandle,[hfile]
	invoke	lstrcpy,file_path,path_buffer
	xchg	[hmemory],ebx
	or	ebx,ebx
	jnz	.free_file_memory
	invoke	GetDlgItem,[hwnddlg_main],ID_PATCHFILE
	invoke	EnableWindow,eax,TRUE
	jmp	.fill_controls
    .free_file_memory:
	invoke	VirtualFree,ebx,0,MEM_RELEASE
    .fill_controls:
	invoke	SetDlgItemText,[hwnddlg_main],IDC_FILEPATH,file_path
	mov	ebx,[hmemory]
	lea	eax,[ebx+DOMAINS_FILE_POINTER+256*0]
	invoke	SetDlgItemText,[hwnddlg_main],IDC_DOMAIN1,eax
	lea	eax,[ebx+DOMAINS_FILE_POINTER+256*1]
	invoke	SetDlgItemText,[hwnddlg_main],IDC_DOMAIN2,eax
	lea	eax,[ebx+DOMAINS_FILE_POINTER+256*2]
	invoke	SetDlgItemText,[hwnddlg_main],IDC_DOMAIN3,eax
	lea	eax,[ebx+CAPTION_POINTER]
	invoke	SetDlgItemTextW,[hwnddlg_main],IDC_CAPTION,eax
	lea	eax,[ebx+SUBCAPTION_POINTER]
	invoke	SetDlgItemTextW,[hwnddlg_main],IDC_SUBCAPTION,eax
	lea	eax,[ebx+MAINMESSAGE_POINTER]
	invoke	SetDlgItemTextW,[hwnddlg_main],IDC_MAINMESSAGE,eax
	lea	eax,[ebx+SECCAPTION_POINTER]
	invoke	SetDlgItemTextW,[hwnddlg_main],IDC_SECCAPTION,eax
	lea	eax,[ebx+SECMESSAGE_POINTER]
	invoke	SetDlgItemTextW,[hwnddlg_main],IDC_SECMESSAGE,eax
	jmp	.done
    .open_error:
	mov	esi,_open_read_error
	jmp	.show_error
    .invalid_file:
	mov	esi,_invalid_file
	jmp	.close_file
    .memory_error:
	mov	esi,_memory_error
	jmp	.close_file
    .read_error:
	mov	esi,_read_error
    .free_memory:
	invoke	VirtualFree,[hmemory],0,MEM_RELEASE
    .close_file:
	invoke	CloseHandle,[hfile]
    .show_error:
	cinvoke wsprintf,text_buffer,esi,name_buffer
	invoke	MessageBox,[hwnddlg_main],text_buffer,_program_title,MB_OK + MB_ICONEXCLAMATION
    .done:
	ret
  endp

  proc patch_file uses ebx esi edi
	invoke	CreateFile,file_path,GENERIC_WRITE,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	cmp	eax,INVALID_HANDLE_VALUE
	je	.open_error
	mov	[hfile],eax
	mov	ebx,[hmemory]
	lea	eax,[ebx+DOMAINS_FILE_POINTER+256*0]
	invoke	GetDlgItemText,[hwnddlg_main],IDC_DOMAIN1,eax,STRING_LENGTH+1
	lea	eax,[ebx+DOMAINS_FILE_POINTER+256*1]
	invoke	GetDlgItemText,[hwnddlg_main],IDC_DOMAIN2,eax,STRING_LENGTH+1
	lea	eax,[ebx+DOMAINS_FILE_POINTER+256*2]
	invoke	GetDlgItemText,[hwnddlg_main],IDC_DOMAIN3,eax,STRING_LENGTH+1
	lea	eax,[ebx+CAPTION_POINTER]
	invoke	GetDlgItemTextW,[hwnddlg_main],IDC_CAPTION,eax,CAPTION_LENGTH+1
	lea	eax,[ebx+SUBCAPTION_POINTER]
	invoke	GetDlgItemTextW,[hwnddlg_main],IDC_SUBCAPTION,eax,SUBCAPTION_LENGTH+1
	lea	eax,[ebx+MAINMESSAGE_POINTER]
	invoke	GetDlgItemTextW,[hwnddlg_main],IDC_MAINMESSAGE,eax,MAINMESSAGE_LENGTH+1
	lea	eax,[ebx+SECCAPTION_POINTER]
	invoke	GetDlgItemTextW,[hwnddlg_main],IDC_SECCAPTION,eax,SECCAPTION_LENGTH+1
	lea	eax,[ebx+SECMESSAGE_POINTER]
	invoke	GetDlgItemTextW,[hwnddlg_main],IDC_SECMESSAGE,eax,SECMESSAGE_LENGTH+1
	invoke	WriteFile,[hfile],[hmemory],SIZE_OF_EXECUTABLE_FILE,bytes_count,0
	or	eax,eax
	jz	.write_error
	invoke	CloseHandle,[hfile]
	cinvoke wsprintf,text_buffer,_patched,name_buffer
	invoke	MessageBox,[hwnddlg_main],text_buffer,_program_title,MB_OK + MB_ICONINFORMATION
	jmp	.done
    .open_error:
	mov	esi,_open_write_error
	jmp	.show_error
    .write_error:
	mov	esi,_write_error
    .close_file:
	invoke	CloseHandle,[hfile]
    .show_error:
	cinvoke wsprintf,text_buffer,esi,name_buffer
	invoke	MessageBox,[hwnddlg_main],text_buffer,_program_title,MB_OK + MB_ICONEXCLAMATION
    .done:
	ret
  endp

section '.data' data readable writeable

  _program_title db 'Patcher',0

  _open_read_error db "Cannot open the file '%s' for reading.",0
  _open_write_error db "Cannot open the file '%s' for writing.",0
  _read_error db "Cannot read the file '%s'.",0
  _write_error db "Cannot write the file '%s'.",0
  _memory_error db "Not enough memory to load the file '%s'.",0
  _invalid_file db "The file '%s' is not a valid executable.",0
  _drop_error db 'Directories are not supported.',0
  _patched db "The file '%s' is patched!",0

  filter db 'All files',0,'*.*',0
	 db 0

section '.bss' readable writeable

  hinstance dd ?
  arguments dd ?
  hwnddlg_main dd ?
  hfile dd ?
  hmemory dd ?

  bytes_count dd ?

  ofn OPENFILENAME

  param_buffer rb 10h
  text_buffer rb 1000h
  name_buffer rb 1000h
  path_buffer rb 4000h
  file_path rb 4000h

section '.idata' import data readable writable

  library kernel32,'KERNEL32.DLL',\
	  user32,'USER32.DLL',\
	  comctl32,'COMCTL32.DLL',\
	  comdlg32,'COMDLG32.DLL',\
	  shell32,'SHELL32.DLL'

  include 'api\kernel32.inc'
  include 'api\user32.inc'
  include 'api\comctl32.inc'
  include 'api\comdlg32.inc'
  include 'api\shell32.inc'

section '.rsrc' resource data readable

  IDC_FILEPATH		= 201
  IDC_DOMAIN1		= 202
  IDC_DOMAIN2		= 203
  IDC_DOMAIN3		= 204
  IDC_CAPTION		= 205
  IDC_SUBCAPTION	= 206
  IDC_MAINMESSAGE	= 207
  IDC_SECCAPTION	= 208
  IDC_SECMESSAGE	= 209

  IDD_MAIN		= 301

  IDI_MAIN		= 401

  ID_OPENFILE		= 1101
  ID_PATCHFILE		= 1102
  ID_GENERATE		= 1103

  directory RT_DIALOG,dialogs,\
	    RT_GROUP_ICON,group_icons,\
	    RT_ICON,icons,\
	    RT_MANIFEST,manifests

  resource dialogs,\
	   IDD_MAIN,LANG_ENGLISH+SUBLANG_DEFAULT,dialog_main

  resource group_icons,\
	   IDI_MAIN,LANG_NEUTRAL,main_icon

  resource icons,\
	   1,LANG_NEUTRAL,main_icon_data

  resource manifests,\
	   1,LANG_NEUTRAL,manifest

  dialog dialog_main,'',0,0,340,380,WS_CAPTION+WS_POPUP+WS_SYSMENU+WS_MINIMIZEBOX+DS_CENTER+DS_MODALFRAME,0,0,'Arial',FONT_SIZE
    dialogitem 'BUTTON','',-1,4,2,332,352,WS_VISIBLE+BS_GROUPBOX
    dialogitem 'EDIT','',IDC_FILEPATH,10,12,264,14,WS_VISIBLE+ES_AUTOHSCROLL+WS_BORDER+ES_READONLY
    dialogitem 'BUTTON','Open File',ID_OPENFILE,280,12,50,14,WS_VISIBLE
    dialogitem 'STATIC','First domain (255 Chars max):',-1,10,30,180,8,WS_VISIBLE
    dialogitem 'EDIT','',IDC_DOMAIN1,10,42,320,14,WS_VISIBLE+WS_BORDER+ES_AUTOHSCROLL
    dialogitem 'STATIC','Alternative domain (255 Chars max):',-1,10,60,180,8,WS_VISIBLE
    dialogitem 'EDIT','',IDC_DOMAIN2,10,72,320,14,WS_VISIBLE+WS_BORDER+ES_AUTOHSCROLL
    dialogitem 'STATIC','Alternative domain (255 Chars max):',-1,10,90,180,8,WS_VISIBLE
    dialogitem 'EDIT','',IDC_DOMAIN3,10,102,320,14,WS_VISIBLE+WS_BORDER+ES_AUTOHSCROLL
    dialogitem 'STATIC','Message in the first window(8 Chars max):',-1,10,120,180,8,WS_VISIBLE
    dialogitem 'EDIT','',IDC_CAPTION,10,132,320,14,WS_VISIBLE+WS_BORDER+ES_AUTOHSCROLL
    dialogitem 'STATIC','Message in the first window(36 Chars max):',-1,10,150,180,8,WS_VISIBLE
    dialogitem 'EDIT','',IDC_SUBCAPTION,10,162,320,14,WS_VISIBLE+WS_BORDER+ES_AUTOHSCROLL
    dialogitem 'STATIC','Message in the first window(544 Chars max):',-1,10,180,180,8,WS_VISIBLE
    dialogitem 'EDIT','',IDC_MAINMESSAGE,10,192,320,56,WS_VISIBLE+WS_BORDER+WS_HSCROLL+WS_VSCROLL+ES_AUTOHSCROLL+ES_AUTOVSCROLL+ES_MULTILINE+ES_WANTRETURN
    dialogitem 'STATIC','Message in the second window(32 Chars max):',-1,10,252,180,8,WS_VISIBLE
    dialogitem 'EDIT','',IDC_SECCAPTION,10,264,320,14,WS_VISIBLE+WS_BORDER+ES_AUTOHSCROLL
    dialogitem 'STATIC','Message in the second window(473 Chars max):',-1,10,282,180,8,WS_VISIBLE
    dialogitem 'EDIT','',IDC_SECMESSAGE,10,294,320,54,WS_VISIBLE+WS_BORDER+WS_HSCROLL+WS_VSCROLL+ES_AUTOHSCROLL+ES_AUTOVSCROLL+ES_MULTILINE+ES_WANTRETURN
    dialogitem 'BUTTON','Patch',ID_PATCHFILE,230,360,50,14,WS_VISIBLE
    dialogitem 'BUTTON','Cancel',IDCANCEL,285,360,50,14,WS_VISIBLE
  enddialog

  icon main_icon,main_icon_data,'patcher.ico'

  resdata manifest
    file 'patcher.manifest'
  endres

section '.reloc' fixups data discardable
