import argparse
from urllib.parse import urlsplit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Vaccine",
        description="Allows you to perform a battery test of SQL injections against a given URL",
        epilog="Piscine Cybersecurity -- smagniny"
    )
    parser.add_argument("-o", help="Archive file, if not specified it will be stored in a default one.", default=None, action="store", type=str)
    parser.add_argument("-X", help="Type of request, if not specified GET will be used.", default=None, action="store", type=str)
    parser.add_argument("URL", help="URLs to run against", nargs='+')
    return parser

class Vaccine:
    def __init__(self, URL: list, ofile:str=None, req:str=None):
        self.ofile:str = ofile
        self.specified_req:str = req
        self.targets:list = URL

    def escuchar():
        pass

    def test_en_bateria(self, url):
        
        # splitted = urlsplit(URL)
        #     protocolo = splitted.scheme
        #     netloc = splitted.netloc
        #     path = splitted.path
        #     query = splitted.query # Nos interesa
        #     fragment = splitted.fragment
        
        #tests
        #escuchar
        pass

    def divoc42():
        '''
        Loop principal
        '''
        # for URL in self.targets:
        #     self.test_en_bateria()
        pass
        
        
if __name__ == "__main__":
    args = build_parser().parse_args()
    vaccine = Vaccine(args.URL, args.o, args.X)

    