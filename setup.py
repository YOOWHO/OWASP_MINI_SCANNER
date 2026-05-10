from setuptools import setup, find_packages

setup(
    name="owasp-mini-scanner",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "jinja2>=3.1.0",
        "flask>=2.3.0",
    ],
    entry_points={
        "console_scripts": [
            "owasp-scanner=scanner.cli:main",
        ],
    },
)
