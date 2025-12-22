
rule Trojan_Win32_Emotet_EFZM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.EFZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 06 46 4f 75 ?? ?? 5f c3 69 05 ?? ?? ?? ?? fd 43 03 00 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}