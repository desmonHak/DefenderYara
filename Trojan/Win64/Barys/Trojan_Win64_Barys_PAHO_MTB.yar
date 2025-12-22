
rule Trojan_Win64_Barys_PAHO_MTB{
	meta:
		description = "Trojan:Win64/Barys.PAHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 ff c6 88 17 48 ff c7 8a 16 01 db 75 ?? 8b 1e 48 83 ee fc 11 db 8a 16 72 e6 } //2
		$a_03_1 = {48 8d be 00 60 01 00 8b 07 09 c0 74 ?? 8b 5f 04 48 8d 8c 30 b4 83 01 00 48 01 f3 48 83 c7 08 ff 15 ?? ?? ?? ?? 48 95 8a 07 48 ff c7 08 c0 74 } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}