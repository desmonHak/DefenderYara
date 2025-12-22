
rule Trojan_BAT_Sdum_NU_MTB{
	meta:
		description = "Trojan:BAT/Sdum.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 04 00 00 0a 72 ?? 00 00 70 73 ?? 00 00 0a 0a 06 72 ?? 00 00 70 6f ?? 00 00 0a de 03 26 de } //2
		$a_01_1 = {73 74 61 74 78 2e 65 78 65 } //1 statx.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}