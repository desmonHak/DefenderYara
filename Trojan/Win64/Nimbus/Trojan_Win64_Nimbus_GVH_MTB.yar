
rule Trojan_Win64_Nimbus_GVH_MTB{
	meta:
		description = "Trojan:Win64/Nimbus.GVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 67 6f 4d 61 72 6b 65 74 69 6e 67 53 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d } //2 VirgoMarketingSolutions.com
	condition:
		((#a_01_0  & 1)*2) >=2
 
}