from distutils.command.clean import clean
from distutils import log
from setuptools import setup
import os

# Get the long description from the README file
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
      name='oco_agent',
      version=__import__('oco_agent').__version__,
      description='Open Source Computer Orchestration Agent - Client/Endpoint & Server Inventory, Configuration Management, Automation and Software Rollout/Deployment/Distribution',
      long_description=long_description,
      long_description_content_type='text/markdown',
      install_requires=[i.strip() for i in open('requirements.txt').readlines()],
      license=__import__('oco_agent').__license__,
      author='Georg Sieber',
      keywords='oco agent computer orchestration management client',
      url=__import__('oco_agent').__website__,
      classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Intended Audience :: System Administrators',
            'Operating System :: POSIX :: Linux',
            'Operating System :: MacOS',
            'Operating System :: Microsoft :: Windows',
            'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
            'Programming Language :: Python',
            'Programming Language :: Python :: 3',
      ],
      packages=[
            'oco_agent',
            'oco_agent.linux',
            'oco_agent.macos',
            'oco_agent.windows',
      ],
      entry_points={
            'console_scripts': [
                  'oco-agent = oco_agent.oco_agent:main',
                  'service-wrapper = oco_agent.service_wrapper:main',
            ],
      },
      platforms=['all'],
      #install_requires=[],
      #test_suite='tests',
)
