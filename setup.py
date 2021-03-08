from setuptools import setup

setup(
    name='ml2ovn-trace',
    version='0.1',
    py_modules=['ml2ovn_trace'],
    install_requires=[
        'Click',
        'openstacksdk',
    ],
    entry_points='''
        [console_scripts]
        ml2ovn-trace=ml2ovn_trace.app:trace
    ''',
)
