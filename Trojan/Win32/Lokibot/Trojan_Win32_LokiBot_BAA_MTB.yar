
rule Trojan_Win32_LokiBot_BAA_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 ca 81 e1 ff 00 00 00 a3 ?? ?? ?? ?? 8a 04 8d } //2
		$a_03_1 = {8b ec 56 8b 75 08 57 8b 7d 0c e8 ?? ?? ?? ?? 30 04 3e 5f 5e 5d } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}