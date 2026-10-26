import sys
import getopt
import random


def help_msg():
    print("""Usage: ./generate --output=file [...]

 --output file      Name of the output file
 --min-length int   Minimum length of generated messages (default: 1)
 --max-length int   Maximum length of generated messages (default: 2^24)
 --count int        Number of messages to generate (default: 1000)
 --help             This message
""")


def main():
    min_length = 1
    max_length = 2**24
    output_file_name = None
    count = 1000
    argv = sys.argv[1:]

    opts, args = getopt.getopt(argv, "", ["min-length=", "max-length=",
                                          "output=", "count=", "help"])

    for opt, arg in opts:
        if opt == "--min-length":
            min_length = int(arg)
        elif opt == "--max-length":
            max_length = int(arg)
        elif opt == "--output":
            output_file_name = arg
        elif opt == "--count":
            count = int(arg)
        elif opt == "--help":
            help_msg()
            sys.exit(0)
        else:
            raise ValueError(f"Unknown option: {opt}")

    if args:
        raise ValueError(f"Unknown options: {args}")

    if not output_file_name:
        raise ValueError("Output file name must be specified")

    rng = random.Random()
    with open(output_file_name, "wb") as output_file:
        for _ in range(count):
            message_len = rng.randint(min_length, max_length)

            message = rng.randbytes(message_len)

            output_file.write(message_len.to_bytes(length=4, byteorder="big"))
            output_file.write(message)


if __name__ == "__main__":
    main()
