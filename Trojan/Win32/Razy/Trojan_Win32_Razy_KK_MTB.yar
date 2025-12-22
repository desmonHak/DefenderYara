
rule Trojan_Win32_Razy_KK_MTB{
	meta:
		description = "Trojan:Win32/Razy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {db 43 00 00 00 09 db 81 ea 01 00 00 00 01 d3 } //20
		$a_01_1 = {0b 01 03 04 00 10 02 00 00 10 00 00 00 30 06 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}