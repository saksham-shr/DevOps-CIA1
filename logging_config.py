"""
Logging configuration for the Report Generator application
"""
import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime

def setup_logging(app):
    """Setup application logging"""
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Configure logging format
    log_format = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s [%(pathname)s:%(lineno)d]'
    )
    
    # File handler with rotation (10MB max, keep 5 backups)
    file_handler = RotatingFileHandler(
        'logs/report_generator.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(log_format)
    
    # Error log handler
    error_handler = RotatingFileHandler(
        'logs/errors.log',
        maxBytes=10*1024*1024,
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(log_format)
    
    # Access log handler
    access_handler = RotatingFileHandler(
        'logs/access.log',
        maxBytes=10*1024*1024,
        backupCount=5
    )
    access_handler.setLevel(logging.INFO)
    access_handler.setFormatter(log_format)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(log_format)
    
    # Set root logger
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.addHandler(error_handler)
    app.logger.addHandler(console_handler)
    
    # Suppress werkzeug default logging
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    
    # Create separate loggers for different components
    report_logger = logging.getLogger('report_generator.report')
    report_logger.setLevel(logging.INFO)
    report_logger.addHandler(file_handler)
    report_logger.addHandler(error_handler)
    
    auth_logger = logging.getLogger('report_generator.auth')
    auth_logger.setLevel(logging.INFO)
    auth_logger.addHandler(file_handler)
    auth_logger.addHandler(error_handler)
    
    db_logger = logging.getLogger('report_generator.database')
    db_logger.setLevel(logging.INFO)
    db_logger.addHandler(file_handler)
    db_logger.addHandler(error_handler)
    
    return app.logger

def log_report_generation(user_id, success=True, error=None, filename=None):
    """Log report generation events"""
    logger = logging.getLogger('report_generator.report')
    if success:
        logger.info(f"Report generated successfully - User: {user_id}, File: {filename}")
    else:
        logger.error(f"Report generation failed - User: {user_id}, Error: {error}")

def log_user_action(user_id, action, details=None):
    """Log user actions"""
    logger = logging.getLogger('report_generator.auth')
    logger.info(f"User action - User: {user_id}, Action: {action}, Details: {details}")

def log_database_error(operation, error):
    """Log database errors"""
    logger = logging.getLogger('report_generator.database')
    logger.error(f"Database error - Operation: {operation}, Error: {error}")

