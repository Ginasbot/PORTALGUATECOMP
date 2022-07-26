from zeep import Client

wsdl = 'AutenticaReg.wsdl'
client = Client(wsdl=wsdl)

client.service.claveHost(info1="00|3130|1|0000000|01S02S03S04S05S06S07S08S09N10S11N12N13N14N15N16N17N18N19N20N21N22N23N24N25N26N27N28N29N30N|LUIS LAVADO                        |MEDIOS ELECTRONICOS          |Su acceso ha sido exitoso                         |1|00000000|000 |                         |")