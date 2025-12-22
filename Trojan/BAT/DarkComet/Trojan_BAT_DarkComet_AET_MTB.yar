
rule Trojan_BAT_DarkComet_AET_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 2b 2b 16 13 04 2b d0 07 11 04 07 11 04 91 09 61 d2 9c 17 13 05 } //2
		$a_01_1 = {1c 1e 33 03 26 2b 01 26 01 11 04 17 58 13 04 19 13 05 } //1 Ḝ̳⬦☁ᄁᜄፘᤄԓ
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}