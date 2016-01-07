'''
# =============================================================================
#      FileName: color_print.py
#          Desc: To get colored output on the terminal
#        Author: Vikas Gupta
#         Email: vikasgupta.nit@gmail.com
#      HomePage:
#       Version: 0.0.1
#    LastChange: 2016-01-07 19:12:46
#       History:
# =============================================================================
'''


class BColors:
    # https://stackoverflow.com/questions/287871/print-in-terminal-with-colors-using-python?answertab=votes#tab-top
    """
        mapping of color to the respective ANSI escape sequence.

    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



def main():
    print BColors.OKBLUE + "warning" + BColors.ENDC

if __name__ == "__main__":
    main()
