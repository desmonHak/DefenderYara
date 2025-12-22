
rule Trojan_Win32_SuspNote_MK{
	meta:
		description = "Trojan:Win32/SuspNote.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {6e 6f 74 65 70 61 64 2e 65 78 65 20 } //notepad.exe   1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {48 4f 57 5f 54 4f 5f 44 45 43 52 59 50 54 2e 74 78 74 } //HOW_TO_DECRYPT.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}