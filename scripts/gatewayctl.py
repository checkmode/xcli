#!/usr/bin/env python3
"""Root-only local recovery and consistent database backup."""
import argparse,datetime,getpass,os,pathlib,sqlite3,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import app
p=argparse.ArgumentParser(description='Xdistribute 管理维护工具')
p.add_argument('action',choices=['backup','reset-password','disable-mfa','status'])
p.add_argument('--output',help='备份数据库绝对路径')
a=p.parse_args()
if os.geteuid()!=0:raise SystemExit('请使用 sudo 执行')
if a.action=='backup':
    backup_root=pathlib.Path('/var/backups/xcli/manual')
    if not a.output:backup_root.mkdir(parents=True,exist_ok=True,mode=0o700);backup_root.chmod(0o700)
    dest=pathlib.Path(a.output) if a.output else backup_root/('gateway-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.sqlite')
    if not dest.is_absolute() or dest.exists():raise SystemExit('目标必须为不存在的绝对路径')
    fd=os.open(dest,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
    with app.db() as src,sqlite3.connect(dest) as dst:src.backup(dst)
    print('数据库已备份：',dest)
elif a.action=='reset-password':
    password=getpass.getpass('新管理密码（至少 16 个字符）：')
    again=getpass.getpass('再次输入：')
    if len(password)<16 or password!=again:raise SystemExit('密码不符合要求或两次输入不一致')
    with app.db() as c:
        c.execute('UPDATE admin SET password=? WHERE id=1',(app.password_hash(password),));c.execute('DELETE FROM sessions');app.audit(c,'password_changed','通过本机维护工具重置')
    print('密码已重置，所有管理会话已退出。')
elif a.action=='disable-mfa':
    if input('仅用于无法使用验证器和恢复码的本机救援。输入 DISABLE MFA 确认：')!='DISABLE MFA':raise SystemExit('已取消')
    with app.db() as c:
        c.execute("UPDATE mfa SET enabled=0,secret='',last_step=-1,pending='',pending_expires=0,pending_session='' WHERE id=1")
        c.execute('DELETE FROM recovery_codes');c.execute('DELETE FROM sessions');c.execute('DELETE FROM mfa_sessions')
        app.audit(c,'mfa_disabled','通过本机 root 救援工具关闭')
    print('二次验证已关闭，所有管理会话已退出。请登录后重新绑定验证器。')
else:
    with app.db() as c:
        for u in c.execute('SELECT * FROM users WHERE deleted=0'):
            print(u['name'],app.user_status(u),'upload='+str(u['upload']),'download='+str(u['download']))
