
rule Trojan_Win32_ClickFix_DHU_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DHU!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffa1 00 ffffffa1 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {24 00 61 00 2b 00 24 00 62 00 2b 00 24 00 63 00 } //50 $a+$b+$c
		$a_00_2 = {2e 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 28 00 24 00 } //10 .Invoke($
		$a_00_3 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*50+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=161
 
}