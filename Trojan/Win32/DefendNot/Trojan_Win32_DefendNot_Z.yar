
rule Trojan_Win32_DefendNot_Z{
	meta:
		description = "Trojan:Win32/DefendNot.Z,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_80_0 = {64 65 66 65 6e 64 6e 6f 74 3a 3a } //defendnot::  2
		$a_80_1 = {64 65 66 65 6e 64 65 72 2d 64 69 73 61 62 6c 65 72 2d 69 70 63 } //defender-disabler-ipc  2
		$a_01_2 = {41 56 20 4e 61 6d 65 20 63 61 6e 20 6e 6f 74 20 62 65 20 65 6d 70 74 79 21 } //1 AV Name can not be empty!
		$a_01_3 = {49 57 73 63 41 53 53 74 61 74 75 73 } //1 IWscASStatus
		$a_01_4 = {49 57 73 63 41 56 53 74 61 74 75 73 34 } //1 IWscAVStatus4
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}