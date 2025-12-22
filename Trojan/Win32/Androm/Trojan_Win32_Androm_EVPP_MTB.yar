
rule Trojan_Win32_Androm_EVPP_MTB{
	meta:
		description = "Trojan:Win32/Androm.EVPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 0e 8d 49 01 88 41 ff 42 8b 45 fc 3b d0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}