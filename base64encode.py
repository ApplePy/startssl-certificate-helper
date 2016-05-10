#! /bin/python3

import os
import sys
import base64


def main():
    if len(sys.argv) > 1:
        for path in sys.argv:
            if os.path.isfile(path) and path != sys.argv[0]:
                with open(path, 'rb') as file:
                    print("{0}: {1}".format(path, base64.b64encode(file.read())))
    exit(0)

if __name__ == "__main__":
    main()
