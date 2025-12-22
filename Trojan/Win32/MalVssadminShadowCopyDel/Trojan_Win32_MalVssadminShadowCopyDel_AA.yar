
rule Trojan_Win32_MalVssadminShadowCopyDel_AA{
	meta:
		description = "Trojan:Win32/MalVssadminShadowCopyDel.AA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 } //1 vssadmin
		$a_00_1 = {64 00 65 00 6c 00 65 00 74 00 65 00 } //1 delete
		$a_00_2 = {73 00 68 00 61 00 64 00 6f 00 77 00 73 00 } //1 shadows
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}