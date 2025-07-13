from setuptools import setup, find_packages

setup(
    name='jwtek',
    version='1.0.0',
    description='JWT Security Analysis & Exploitation Tool',
    author='Parth',
    packages=find_packages(),
    install_requires=[
        'pyjwt',
        'tqdm',
        'requests',
        'termcolor',
        # add others as needed
    ],
    entry_points={
        'console_scripts': [
            'jwtek = jwtek.__main__:main',
        ],
    },
    python_requires='>=3.6',
)
