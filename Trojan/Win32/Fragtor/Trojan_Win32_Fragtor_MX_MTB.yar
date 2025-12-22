
rule Trojan_Win32_Fragtor_MX_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {db 45 fc 99 b9 64 00 00 00 f7 f9 83 ec 08 dd 1c 24 42 } //1
		$a_01_1 = {77 00 69 00 6e 00 64 00 71 00 2e 00 76 00 33 00 } //1 windq.v3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}