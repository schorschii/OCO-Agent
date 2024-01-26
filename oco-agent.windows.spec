# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


def Entrypoint(dist, group, name, **kwargs):
    import pkg_resources

    # get toplevel packages of distribution from metadata
    def get_toplevel(dist):
        distribution = pkg_resources.get_distribution(dist)
        if distribution.has_metadata('top_level.txt'):
            return list(distribution.get_metadata('top_level.txt').split())
        else:
            return []

    kwargs.setdefault('hiddenimports', [])
    packages = []
    for distribution in kwargs['hiddenimports']:
        packages += get_toplevel(distribution)

    kwargs.setdefault('pathex', [])
    # get the entry point
    ep = pkg_resources.get_entry_info(dist, group, name)
    # insert path of the egg at the verify front of the search path
    kwargs['pathex'] = [ep.dist.location] + kwargs['pathex']
    # script name must not be a valid module name to avoid name clashes on import
    script_path = os.path.join(workpath, name + '-script.py')
    print("creating script for entry point", dist, group, name)
    with open(script_path, 'w') as fh:
        print("import", ep.module_name, file=fh)
        print("%s.%s()" % (ep.module_name, '.'.join(ep.attrs)), file=fh)
        for package in packages:
            print("import", package, file=fh)

    return Analysis(
        [script_path] + kwargs.get('scripts', []),
        **kwargs
    )


agent_a = Entrypoint('oco_agent', 'console_scripts', 'oco-agent',
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
wrapper_a = Entrypoint('oco_agent', 'console_scripts', 'service-wrapper',
    datas=[],
    #hiddenimports=['win32timezone'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)
MERGE( (agent_a, 'oco-agent', 'oco-agent'), (wrapper_a, 'service-wrapper', 'service-wrapper') )

agent_pyz = PYZ(agent_a.pure, agent_a.zipped_data, cipher=block_cipher)
agent_exe = EXE(agent_pyz, agent_a.scripts, [],
          exclude_binaries=True,
          name='oco-agent',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True,
          contents_directory='.',
          icon='assets\\logo.ico')

wrapper_pyz = PYZ(wrapper_a.pure, wrapper_a.zipped_data, cipher=block_cipher)
wrapper_exe = EXE(wrapper_pyz, wrapper_a.scripts, [],
          exclude_binaries=True,
          name='service-wrapper',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True,
          contents_directory='.',
          icon='assets\\logo-service.ico')

agent_coll = COLLECT(agent_exe, agent_a.binaries, agent_a.zipfiles, agent_a.datas,
               wrapper_exe, wrapper_a.binaries, wrapper_a.zipfiles, wrapper_a.datas,
               strip=False,
               upx=True,
               upx_exclude=[],
               name='oco-agent')
