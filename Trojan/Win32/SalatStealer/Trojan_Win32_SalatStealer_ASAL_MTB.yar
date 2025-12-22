
rule Trojan_Win32_SalatStealer_ASAL_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.ASAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {95 88 44 0a 01 95 40 83 c2 02 83 f8 31 7d 3b 0f b6 9c 04 87 00 00 00 89 dd c0 eb 04 0f b6 db 8d 35 2d 4f 97 00 0f b6 1c 1e 83 fa 62 0f 83 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}