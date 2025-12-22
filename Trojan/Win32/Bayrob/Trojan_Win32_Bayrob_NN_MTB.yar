
rule Trojan_Win32_Bayrob_NN_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af d1 89 15 ?? ?? ?? 00 89 04 24 c7 44 24 04 } //2
		$a_03_1 = {8b 4e 04 66 8b 15 ?? ?? ?? 00 0f bf d2 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}