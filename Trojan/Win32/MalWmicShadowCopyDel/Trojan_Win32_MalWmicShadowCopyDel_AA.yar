
rule Trojan_Win32_MalWmicShadowCopyDel_AA{
	meta:
		description = "Trojan:Win32/MalWmicShadowCopyDel.AA,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {77 00 6d 00 69 00 63 00 [0-10] 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 [0-10] 64 00 65 00 6c 00 65 00 74 00 65 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}