
rule Trojan_Win64_NukeSped_GXF_MTB{
	meta:
		description = "Trojan:Win64/NukeSped.GXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {5a 4e 33 36 33 4e 64 64 00 6e 74 64 6c 6c } //5 乚㘳丳摤渀摴汬
		$a_01_1 = {45 36 50 20 43 4d 5c 31 73 46 45 6f 42 44 54 57 33 4b 6f 31 45 00 00 00 00 74 78 34 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}