from scapy.all import *
from scapy.contrib import gtp
import time
import argparse
import logging
import sys

parser = argparse.ArgumentParser()
parser.add_argument("-l", "--loop", help="Choose option to loop", action='store_true')
parser.add_argument("-i", "--IP", help="Provide a list of IPs to monitor", type=str)
parser.add_argument("-log", "--LOG", help="Choose option to log to file", action='store_true')
parser.add_argument("-d", "--DEBUG", help="Choose option to enable debug mode", action='store_true')
parser.add_argument("-nv", "--NOVERBOSE", help="Choose option to output log INFO to stderr", action='store_true')
args = parser.parse_args()

# Init Logger

logger = logging.getLogger('gtp_echo_monitoring')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Init Console Handler for Error Messages
if not args.NOVERBOSE:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

if args.LOG:
    # Create File Handler which Logs up to ERROR Messages
    fh = logging.FileHandler('info.log')
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

# Create File Handler which Logs Debug Messages
if args.DEBUG:
    dh = logging.FileHandler('debug.log')
    dh.setLevel(logging.DEBUG)
    dh.setFormatter(formatter)
    logger.addHandler(dh)

restart_counter_dict = dict()


def validate_response(pkt):
    try:
        if args.DEBUG:
            logger.debug('Packet: {}'.format(pkt.summary))
            logger.debug('IE_LIST: {}'.format(pkt.IE_list))
        for ie in pkt.IE_list:
            if ie.ietype == 14:
                restart_counter = ie.restart_counter
            else:
                restart_counter = None
    except Exception as exc:
        restart_counter = None
        logger.error(exc)
        pass

    logger.debug('Getting Previous value of Restart Counter from GSN IP: {}'.format(pkt.getlayer(IP).src))
    previous_restart_counter = restart_counter_dict.get(pkt.getlayer(IP).src)

    if restart_counter:
        if previous_restart_counter:
            result = previous_restart_counter == restart_counter
            if args.DEBUG:
                logger.debug('Updated Restart Counter Value: {}'.format(restart_counter))
                logger.debug('Previous Restart Counter Value: {}'.format(previous_restart_counter))
                logger.debug('Result of GSN IP: {} is {}'.format(pkt.getlayer(IP).src, result))

        else:
            restart_counter_dict.update({pkt.getlayer(IP).src: restart_counter})
            logger.debug('No Previous value of Restart Counter from GSN IP: {}'.format(pkt.getlayer(IP).src))
            logger.debug('First Restart Counter Value: {}'.format(restart_counter))
            result = True
            return result
    else:
        logger.error('No Restart Counter Found on Packet: {}'.format(pkt.summary()))
        logger.debug('No Restart Counter Found on Packet: {}'.format(pkt.summary()))
        result = False

    logger.debug('GTP Interface has not been restarted' if result else 'GTP Interface has been restarted')
    return result


def main():
    if args.IP:
        ip_lst = args.IP.split(',')
        logger.info('GTP Interfaces IP list: {}'.format(ip_lst))
        echo_request = IP(dst=ip_lst) / UDP(sport=2123, dport=2123) / gtp.GTPHeader() / gtp.GTPEchoRequest()

        if args.DEBUG:
            logger.debug('List of Echo Request Packets Generated: {}'.format([p for p in echo_request]))

    else:
        logger.error('Must Specify an IP')
        if args.DEBUG:
            logger.debug("Could not find any IP on user's input")
        sys.exit()

    if args.loop:
        logger.info('######## LOOP Initiated ########')
        while True:
            try:
                ans, uans = sr(echo_request, verbose=False, timeout=5)
                if len(uans):
                    for i in range(len(uans)):
                        gtp_ip = uans[i].getlayer(IP).dst
                        logger.warning('GTP Interface: {} || Status: {} || Cause: {}'.format(gtp_ip, 'NOK', 'TIMEOUT'))

                if len(ans):
                    for i in range(len(ans)):
                        gtp_ip = ans[i][0].getlayer(IP).dst
                        status = "OK" if validate_response(ans[i][1]) else "NOK"
                        if status == 'OK':
                            logger.info('GTP Interface: {} || Status: {}'.format(gtp_ip, status))
                        else:
                            logger.warning('GTP Interface: {} || Status: {} || Cause: {}'.format(gtp_ip, 'NOK',
                                                                                                 'RestartCounter Changed'))
                logger.debug('TIMEOUT: 60s')
                time.sleep(60)
            except Exception as exc:
                logger.error(exc)
                if args.DEBUG:
                    logger.warning('While trying to send packet got an exception.')
                    logger.debug(exc)
                continue
    else:
        logger.info('Sending Packets...')
        try:
            ans, uans = sr(echo_request, verbose=False, timeout=5)
            if len(uans):
                for i in range(len(uans)):
                    gtp_ip = uans[i].getlayer(IP).dst
                    logger.warning('GTP Interface: {} || Status: {} || Cause: {}'.format(gtp_ip, 'NOK', 'TIMEOUT'))

            if len(ans):
                for i in range(len(ans)):
                    gtp_ip = ans[i][0].getlayer(IP).dst
                    status = "OK" if validate_response(ans[i][1]) else "NOK"
                    if status == 'OK':
                        logger.info('GTP Interface: {} || Status: {}'.format(gtp_ip, status))
                    else:
                        logger.warning('GTP Interface: {} || Status: {} || Cause: {}'.format(gtp_ip, 'NOK',
                                                                                             'RestartCounter Changed'))
            logger.debug('TIMEOUT: 60s')
            time.sleep(60)
        except Exception as exc:
            logger.error(exc)
            if args.DEBUG:
                logger.warning('While trying to send packet got an exception.')
                logger.debug(exc)


if __name__ == "__main__":
    main()
