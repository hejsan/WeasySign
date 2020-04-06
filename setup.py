from setuptools import setup

setup(
    name='WeasySign',
    version='52',  # Equal to the next version of WeasyPrint
    description='Digital Signatures for WeasyPrint',
    url='https://github.com/hejsan/WeasySign',
    author='Bjarni Thorisson',
    author_email='hr.bjarni@gmail.com',
    license='BSD',
    packages=['weasysign'],
    zip_safe=False
)

