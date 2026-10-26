import sys
import getopt
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87


def help_msg():
    """Print the help message."""

    print(f"""Usage: {sys.argv[0]} [...]

 --signatures file   File to output signatures to
 --messages file     File to read the messages from (the file should have
                     big-endian length-prefixed messages to read)
 --seeds file        File with private key seeds to read
 --algorithm name    Name of algorithm to use: "ML-DSA-44", "ML-DSA-65", or
                     "ML-DSA-87"
 --help              This message
""")

def main():
    algorithm_name = None
    sig_file_name = None
    sig_file = None
    message_file_name = None
    message_file = None
    seeds_file_name = None
    seeds_file = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "",
        ["help", "signatures=", "messages=", "seeds=", "algorithm="])

    for opt, arg in opts:
        if opt == "--help":
            help_msg()
            sys.exit(0)
        elif opt == "--signatures":
            sig_file_name = arg
        elif opt == "--messages":
            message_file_name = arg
        elif opt == "--seeds":
            seeds_file_name = arg
        elif opt == "--algorithm":
            algorithm_name = arg
        else:
            raise ValueError(f"Unrecognised argument: {opt}")

    if args:
        raise ValueError(f"Unrecognised options: {args}")

    if not all([algorithm_name, sig_file_name, message_file_name,
                seeds_file_name]):
        raise ValueError("The algorithm, and file names of messages, "
            "signatures and seeds must be specified")

    if algorithm_name == "ML-DSA-44":
        algorithm = ML_DSA_44
    elif algorithm_name == "ML-DSA-65":
        algorithm = ML_DSA_65
    elif algorithm_name == "ML_DSA_87":
        algorithm = ML_DSA_87
    else:
        raise ValueError("Unrecognised algorithm name")

    try:
        sig_file = open(sig_file_name, "wb")
        message_file = open(message_file_name, "rb")
        seeds_file = open(seeds_file_name, "rb")

        while True:
            seed = seeds_file.read(32)
            if len(seed) == 0:
                break
            if len(seed) != 32:
                raise ValueError("Seeds file not a multiple of 32 bytes!")

            message_len = int.from_bytes(message_file.read(4), "big")
            message = message_file.read(message_len)
            if len(message) != message_len:
                raise ValueError("Truncated message file")

            pk, sk = algorithm.key_derive(seed)

            sig = algorithm.sign(sk, message, deterministic = True)

            sig_file.write(sig)
    finally:
        if sig_file:
            sig_file.close()
        if message_file:
            message_file.close()
        if seeds_file:
            seeds_file.close()


if __name__ == '__main__':  # pragma: no cover
    main()
