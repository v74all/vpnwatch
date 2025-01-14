import os
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler, MemoryHandler
import colorama
from colorama import Fore, Style
import threading
try:
    from apscheduler.schedulers.background import BackgroundScheduler
except ImportError:
    BackgroundScheduler = None

class LoggerSingleton:
    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_logger(cls, name: str = 'V7lthronyx') -> logging.Logger:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls._create_logger(name)
            return cls._instance

    @classmethod
    def _create_logger(cls, name: str) -> logging.Logger:
        colorama.init(autoreset=True)

        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)

        if logger.handlers:
            return logger

        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(
            log_dir,
            f'{name.lower()}_{datetime.now().strftime("%Y%m%d")}.log'
        )

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)

        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )
        file_handler.setFormatter(file_formatter)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(cls.ColoredFormatter())

        emergency_handler = MemoryHandler(
            capacity=10240,
            flushLevel=logging.ERROR,
            target=file_handler
        )
        logger.addHandler(emergency_handler)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        def log_memory_usage(logger):
            import psutil
            process = psutil.Process()
            mem_info = process.memory_info()
            logger.debug(f"Memory usage: {mem_info.rss / 1024 / 1024:.2f} MB")

        if BackgroundScheduler:
            memory_handler = logging.handlers.MemoryHandler(
                capacity=1024,
                flushLevel=logging.ERROR,
                target=file_handler,
                flushOnClose=True
            )
            scheduler = BackgroundScheduler()
            scheduler.add_job(log_memory_usage, 'interval', minutes=5, args=[logger])
            scheduler.start()
            logger.addHandler(memory_handler)

        return logger

    @classmethod
    def log_scan_results(cls, results: dict):
        logger = cls.get_logger()
        logger.info("Scan Results:")
        for key, value in results.items():
            logger.info(f"{key}: {value}")

    class ColoredFormatter(logging.Formatter):
        FORMATS = {
            logging.DEBUG: Fore.CYAN + '%(asctime)s - %(levelname)s - %(message)s' + Style.RESET_ALL,
            logging.INFO: Fore.GREEN + '%(asctime)s - %(levelname)s - %(message)s' + Style.RESET_ALL,
            logging.WARNING: Fore.YELLOW + '%(asctime)s - %(levelname)s - %(message)s' + Style.RESET_ALL,
            logging.ERROR: Fore.RED + '%(asctime)s - %(levelname)s - %(message)s' + Style.RESET_ALL,
            logging.CRITICAL: Fore.RED + Style.BRIGHT + '%(asctime)s - %(levelname)s - %(message)s' + Style.RESET_ALL
        }
        DATEFMT = '%Y-%m-%d %H:%M:%S'

        def format(self, record: logging.LogRecord) -> str:
            log_fmt = self.FORMATS.get(record.levelno, '%(asctime)s - %(levelname)s - %(message)s')
            formatter = logging.Formatter(log_fmt, datefmt=self.DATEFMT)
            return formatter.format(record)

if __name__ == "__main__":
    logger = LoggerSingleton.get_logger()

    logger.debug("This is a DEBUG message.")
    logger.info("This is an INFO message.")
    logger.warning("This is a WARNING message.")
    logger.error("This is an ERROR message.")
    logger.critical("This is a CRITICAL message.")
