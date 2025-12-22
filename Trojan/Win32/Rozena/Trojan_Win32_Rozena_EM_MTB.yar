
rule Trojan_Win32_Rozena_EM_MTB{
	meta:
		description = "Trojan:Win32/Rozena.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 00 0f be c0 34 ff 89 c2 8b 84 24 14 04 00 00 89 44 24 04 89 14 24 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}