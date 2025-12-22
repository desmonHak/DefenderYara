
rule HackTool_Win95_HeldPony_C{
	meta:
		description = "HackTool:Win95/HeldPony.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 5c 00 62 00 74 00 64 00 6c 00 67 00 2e 00 6a 00 73 00 } //1 C:\Users\Public\Controller\btdlg.js
	condition:
		((#a_00_0  & 1)*1) >=1
 
}