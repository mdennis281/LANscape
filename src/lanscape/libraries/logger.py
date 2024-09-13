import logging
from logging.handlers import RotatingFileHandler


def configure_logging(loglevel:str, logfile:bool):
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {loglevel}')
    print(f'loglevel: {numeric_level} - {loglevel}')
    
    
    logging.basicConfig(level=numeric_level, format='[%(name)s] %(levelname)s - %(message)s')
    
    if logfile:
        handler = RotatingFileHandler('lanscape.log', maxBytes=100000, backupCount=3)
        handler.setLevel(numeric_level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
    else:
        # For console, it defaults to basicConfig
        pass
    