
rule HackTool_Win32_SecureDelete_A{
	meta:
		description = "HackTool:Win32/SecureDelete.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {5c 00 73 00 62 00 2d 00 73 00 65 00 63 00 75 00 72 00 65 00 2d 00 64 00 65 00 6c 00 65 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //1 \sb-secure-delete.exe
	condition:
		((#a_00_0  & 1)*1) >=1
 
}