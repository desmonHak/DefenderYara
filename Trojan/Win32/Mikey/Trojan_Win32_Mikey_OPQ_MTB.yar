
rule Trojan_Win32_Mikey_OPQ_MTB{
	meta:
		description = "Trojan:Win32/Mikey.OPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 31 ff 45 89 fc 41 83 e4 03 46 8a 64 24 28 47 30 24 3b 4d 8d 67 01 4d 89 e7 4c 39 e1 75 e4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}