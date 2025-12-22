
rule Trojan_Win64_Lazy_NS_MTB{
	meta:
		description = "Trojan:Win64/Lazy.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 46 08 88 07 49 63 46 04 41 3b 06 7e 07 49 8d 3c 07 c6 07 cc } //2
		$a_01_1 = {8d 83 00 10 00 00 4c 63 e0 49 8b } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}