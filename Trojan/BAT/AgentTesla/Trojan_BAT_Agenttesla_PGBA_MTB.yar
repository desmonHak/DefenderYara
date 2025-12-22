
rule Trojan_BAT_Agenttesla_PGBA_MTB{
	meta:
		description = "Trojan:BAT/Agenttesla.PGBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_80_0 = {73 59 67 63 64 76 67 4a 6c 2f 53 66 71 49 4d 63 48 7a 46 30 6b 6a 30 74 65 73 6a 43 55 76 35 70 67 54 6a 6d 73 4e 63 55 4c 68 52 4b 77 45 59 37 67 49 39 74 34 31 41 67 32 36 46 71 45 57 66 71 } //sYgcdvgJl/SfqIMcHzF0kj0tesjCUv5pgTjmsNcULhRKwEY7gI9t41Ag26FqEWfq  5
	condition:
		((#a_80_0  & 1)*5) >=5
 
}