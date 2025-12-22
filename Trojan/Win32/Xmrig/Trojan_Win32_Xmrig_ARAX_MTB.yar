
rule Trojan_Win32_Xmrig_ARAX_MTB{
	meta:
		description = "Trojan:Win32/Xmrig.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 46 10 8d 04 45 02 00 00 00 50 51 6a 01 6a 00 52 ff b5 ?? ff ff ff ff 15 08 20 41 00 } //2
		$a_01_1 = {5c 75 70 64 61 74 65 72 2e 70 64 62 } //2 \updater.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}