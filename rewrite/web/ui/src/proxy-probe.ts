export type ProbeState = 'waiting' | 'testing' | 'success' | 'failed';
export type ProbeReason = 'invalid_format' | 'invalid_address' | 'invalid_port' | 'invalid_credentials' | 'invalid_link' | 'duplicate' | 'unavailable' | 'timeout' | 'invalid_exit' | 'invalid_dns' | 'dns_unavailable';
export type ProxyPreviewRow = {
  tag?: string; label?: string; exit_ip?: string; country?: string; port?: number; hysteria2?: boolean;
  index?: number; line?: number; state?: ProbeState; reason?: ProbeReason; address?: string; https_ms?: number; doh_ms?: number;
};
export const probeStates: readonly string[] = ['waiting', 'testing', 'success', 'failed'];
export const probeReasons: readonly string[] = ['invalid_format', 'invalid_address', 'invalid_port', 'invalid_credentials', 'invalid_link', 'duplicate', 'unavailable', 'timeout', 'invalid_exit', 'invalid_dns', 'dns_unavailable'];
export function probeReason(reason?: ProbeReason): string {
  return ({ invalid_format:'格式不正确，请使用 IP:端口:账号:密码。', invalid_address:'地址不是有效的公网 IPv4。', invalid_port:'代理端口不正确。',
    invalid_credentials:'账号或密码格式不正确。', invalid_link:'VMess 链接无效或包含不支持的配置。', duplicate:'地址和端口重复，或已存在于代理列表中。',
    unavailable:'连接或探测未通过，请检查地址、协议、认证及网络。', timeout:'检测超时，请检查代理和网络。',
    invalid_exit:'未能取得有效的公网出口或服务器地址。', invalid_dns:'DNS 检测未通过。', dns_unavailable:'DNS 检测服务无法访问。' } as Record<ProbeReason,string>)[reason ?? 'unavailable'];
}
export function probeTitle(row: ProxyPreviewRow): string {
  return `第 ${row.line ?? row.index ?? '—'} 行${row.address && row.port ? ` · ${row.address}:${row.port}` : ''}`;
}
