from setuptools import setup, find_packages

setup(
    name='honeyscanner',
    version='0.1.0',
    description='A vulnerability analyzer for honeypots',
    author='Aristofanis Chionis Koufakos',
    author_email='aristofanischionis@gmail.com',
    url='https://github.com/honeynet/honeyscanner/',
    license="MIT",
    packages=find_packages(),
    python_requires="==3.9",
    install_requires=[
        "Flask==2.0.1",
        "Flask-Cors==3.0.10",
        "gevent==21.8.0",
        "requests==2.26.0",
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    entry_points={
        'console_scripts': [
            'honeyscanner=honeyscanner.main:main',
            'honeyscanner-webapp=honeyscanner.webapp.app:run'
        ],
    },
)
