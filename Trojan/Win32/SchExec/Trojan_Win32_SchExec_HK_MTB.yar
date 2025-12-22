
rule Trojan_Win32_SchExec_HK_MTB{
	meta:
		description = "Trojan:Win32/SchExec.HK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 20 00 2d 00 61 00 64 00 64 00 73 00 74 00 6f 00 72 00 65 00 20 00 2d 00 66 00 20 00 72 00 6f 00 6f 00 74 00 20 00 } //1 certutil -addstore -f root 
	condition:
		((#a_00_0  & 1)*1) >=1
 
}