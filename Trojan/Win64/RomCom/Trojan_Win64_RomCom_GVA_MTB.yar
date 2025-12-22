
rule Trojan_Win64_RomCom_GVA_MTB{
	meta:
		description = "Trojan:Win64/RomCom.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 10 48 ff c0 49 83 c1 02 49 83 f9 18 0f 84 } //2
		$a_02_1 = {45 31 c0 41 80 fa 2b 41 0f 94 c0 49 01 c8 47 0f b6 5c 01 fe 41 8d 73 bf 83 e6 ?? 83 c6 0a 41 8d 53 d0 41 83 fb 3a 0f 43 d6 83 fa 0f } //1
	condition:
		((#a_01_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}