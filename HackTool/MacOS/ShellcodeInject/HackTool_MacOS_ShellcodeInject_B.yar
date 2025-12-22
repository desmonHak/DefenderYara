
rule HackTool_MacOS_ShellcodeInject_B{
	meta:
		description = "HackTool:MacOS/ShellcodeInject.B,SIGNATURE_TYPE_MACHOHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {21 0c 8e d2 01 0e a0 f2 e1 83 1f f8 61 ac 8e d2 81 2d ac f2 81 ee cd f2 41 ce e5 f2 e1 03 1f f8 21 ed 8d d2 c1 6d ae f2 e1 65 } //1
		$a_00_1 = {c8 f2 21 8c ed f2 e1 83 1e f8 21 08 8e d2 01 8e ad f2 21 6d cc f2 21 8c ee f2 e1 03 1e f8 e1 65 8a d2 21 6f ae f2 81 ae cc f2 } //1
		$a_00_2 = {a1 ed e5 f2 e1 83 1d f8 e1 e5 8d d2 01 ae ac f2 c1 0d c0 f2 e1 03 1d f8 e1 a5 8e d2 61 4e ae f2 e1 45 cc f2 21 cd ed f2 e1 83 } //1
		$a_00_3 = {1c f8 ff 03 1c f8 01 05 80 d2 e1 63 21 cb e1 83 1b f8 01 07 80 d2 e1 63 21 cb e1 03 1b f8 e0 03 01 aa e1 43 01 d1 e2 03 1f aa 70 07 80 d2 e1 66 02 d4 } //1
		$a_00_4 = {5f 76 6d 5f 70 72 6f 74 65 63 74 } //1 _vm_protect
		$a_00_5 = {5f 6d 61 63 68 5f 76 6d 5f 61 6c 6c 6f 63 61 74 65 } //1 _mach_vm_allocate
		$a_00_6 = {5f 6d 61 63 68 5f 76 6d 5f 77 72 69 74 65 } //1 _mach_vm_write
		$a_00_7 = {5f 74 68 72 65 61 64 5f 63 72 65 61 74 65 5f 72 75 6e 6e 69 6e 67 } //1 _thread_create_running
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}