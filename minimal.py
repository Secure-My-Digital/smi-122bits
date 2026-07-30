
from lib.encodings import Base91, Base95
import crypto
crypto.ENCODING = Base91
from crypto import *

from lib.entropy import *
from lib.report import *

def main():
    banner()
    ikm = load_ikm()
    prk = derive_prk(ikm)
    stats = Welford()
    for i in range(MAX_ITERATIONS):
        stats.update(shannon_entropy(generate_password(prk,i)))
    summary(stats)
if __name__=='__main__':
    main()
