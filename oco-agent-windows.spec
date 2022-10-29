# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


agent_a = Analysis(['oco-agent.py'],
             pathex=['.'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
wrapper_a = Analysis(['service-wrapper.py'],
             pathex=['.'],
             binaries=[],
             datas=[],
             hiddenimports=['win32timezone'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
MERGE( (agent_a, 'oco-agent', 'oco-agent'), (wrapper_a, 'service-wrapper', 'service-wrapper') )

agent_pyz = PYZ(agent_a.pure, agent_a.zipped_data, cipher=block_cipher)
agent_exe = EXE(agent_pyz, agent_a.scripts, [],
          exclude_binaries=True,
          name='oco-agent',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True , icon='assets\\logo.ico')

wrapper_pyz = PYZ(wrapper_a.pure, wrapper_a.zipped_data, cipher=block_cipher)
wrapper_exe = EXE(wrapper_pyz, wrapper_a.scripts, [],
          exclude_binaries=True,
          name='service-wrapper',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True , icon='assets\\logo-service.ico')

agent_coll = COLLECT(agent_exe, agent_a.binaries, agent_a.zipfiles, agent_a.datas,
               wrapper_exe, wrapper_a.binaries, wrapper_a.zipfiles, wrapper_a.datas,
               strip=False,
               upx=True,
               upx_exclude=[],
               name='oco-agent')
