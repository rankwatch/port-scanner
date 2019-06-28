# Port Scanner
Django Application to scan open ports across your infrastructure and provide a detailed report of any security alerts.

# Installation

1) Clone the repository.

2) To run with UWSGI: 
    
    - Modify the ```sample_uwsgi.ini``` as per your system
    
    - Configure nginx - specify path to uwsgi_params
    
    - Specify Time Zone information and Celery backend server information in ```CONFIG.ini```
    
    - Make migrations:
        
        * ```python manage.py makemigrations OpenPorts```
        
        * ```python manage.py migrate```
        
        * Create superuser (optional) - ```python manage.py createsuperuser```

    - Run with ```uwsgi --ini /path-to-your-ini-file```

3) To run with django server:
    
    - Modify ```CONFIG.ini``` as per your requirements
    
    - Make migrations:
        
        * ```python manage.py makemigrations OpenPorts```
        
        * ```python manage.py migrate```
        
        * Create superuser (optional) - ```python manage.py createsuperuser```

    - Run with ```python manage.py runserver 0.0.0.0:8000```

        * ```0.0.0.0:8000``` is optional, specify any address you want

# Usage

1) Login with your credentials created by the administrator.

2) Primary Navbar:
    
    * Settings Menu:
        
        - Configure your global settings
        
        - Mention the secured and unsecured proxy ips
        
        - Specify a crontab formatted schedule m:h:d:mD:MY, to run scheduled scans
    
    * Logout

3) Secondary Navbar:
    
    * View Dashboard:
    
        - Gives you overview of any security alerts for all the added hosts
    
    * View All Hosts:
    
        - Tabular view of all the added hosts and their latest scan summary
    
    * Alerts
    
        - Number of unattended alerts
    
    * Report:
    
        - Secure Scan Report summary and option to view past scan reports
    
        - Open Scan Report summary and option to view past scan reports
    
    * Add Host:
    
        - Add a host to initiate scans for
    
    * Help:
    
        - View this help
