"""SSH 远程连接元工具
使用 Paramiko 实现 SSH 远程连接和命令执行。

支持两种模式：
1. 阻塞模式：一次性执行命令并返回完整结果（适用于 df -h, ps aux 等简单查询）
2. 流式模式：持续输出命令（适用于 tail -f, watch, sudo 等需要实时交互的场景）

流式模式特点：
- 维护输出缓冲区，支持历史回顾
- 支持动态决策：LLM 可根据实时输出决定下一步操作
- 支持用户交互（如 sudo 密码输入）

使用方法：
    session = SSHSession()
    session.connect(host, port, username, password/key)
    result = session.execute_and_return("df -h")  # 阻塞模式
    session.start_streaming("tail -f /var/log/syslog")  # 流式模式
    output = session.read_output()  # 读取缓冲区
    session.close()
"""

import os
import sys
import time
import json
import threading
import queue
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

try:
    import paramiko
except ImportError:
    paramiko = None


@dataclass
class CommandResult:
    """命令执行结果"""
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    session_id: str = ""


@dataclass
class StreamingSession:
    """流式会话状态"""
    session_id: str
    channel: paramiko.Channel
    thread: threading.Thread
    output_buffer: List[str] = field(default_factory=list)
    error_buffer: List[str] = field(default_factory=list)
    is_running: bool = True
    exit_code: Optional[int] = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    output_file: Optional[str] = None  # 可选：持久化到文件

    def append_output(self, data: str):
        with self.lock:
            self.output_buffer.append(data)
            if self.output_file:
                try:
                    with open(self.output_file, 'a', encoding='utf-8') as f:
                        f.write(data)
                except:
                    pass

    def append_error(self, data: str):
        with self.lock:
            self.error_buffer.append(data)
            if self.output_file:
                try:
                    with open(self.output_file, 'a', encoding='utf-8') as f:
                        f.write(f"[STDERR] {data}")
                except:
                    pass

    def get_full_output(self) -> str:
        with self.lock:
            return ''.join(self.output_buffer)

    def get_full_error(self) -> str:
        with self.lock:
            return ''.join(self.error_buffer)

    def get_recent_output(self, lines: int = 50) -> str:
        with self.lock:
            return ''.join(self.output_buffer[-lines:])

    def get_output_since(self, marker: str) -> str:
        """获取从指定标记之后的所有输出"""
        with self.lock:
            full = ''.join(self.output_buffer)
            idx = full.find(marker)
            if idx >= 0:
                return full[idx + len(marker):]
            return full


class SSHSession:
    """SSH 会话管理器
    
    支持阻塞和流式两种执行模式。
    线程安全，支持多个并发流式会话。
    """
    
    def __init__(self):
        self.client: Optional[paramiko.SSHClient] = None
        self.host: Optional[str] = None
        self.port: int = 22
        self.username: Optional[str] = None
        self.connected: bool = False
        self.lock = threading.Lock()
        self.streaming_sessions: Dict[str, StreamingSession] = {}
        self._session_counter = 0
    
    def connect(self, host: str, port: int = 22, username: str = "root",
                password: Optional[str] = None, key_filename: Optional[str] = None,
                timeout: int = 10, known_hosts_policy: str = "auto") -> Dict[str, Any]:
        """连接到远程服务器
        
        Args:
            host: 主机地址
            port: SSH 端口，默认 22
            username: 用户名，默认 root
            password: 密码（与 key_filename 二选一）
            key_filename: 私钥文件路径
            timeout: 连接超时（秒）
            known_hosts_policy: 主机密钥验证策略
                - "auto": 自动添加未知主机（默认）
                - "strict": 严格验证
                - "none": 不验证
        
        Returns:
            包含连接状态的字典
        """
        if paramiko is None:
            return {"status": "error", "msg": "Paramiko 未安装，请运行: pip install paramiko"}
        
        try:
            self.client = paramiko.SSHClient()
            
            # 设置主机密钥策略
            if known_hosts_policy == "strict":
                self.client.load_system_host_keys()
            elif known_hosts_policy == "auto":
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            else:  # none
                self.client.set_missing_host_key_policy(paramiko.WarningPolicy())
            
            connect_kwargs = {
                "hostname": host,
                "port": port,
                "username": username,
                "timeout": timeout,
            }
            
            if password:
                connect_kwargs["password"] = password
            if key_filename:
                connect_kwargs["key_filename"] = key_filename
            
            # 如果没有提供密码和密钥，尝试 "none" 认证（服务器可能接受无认证）
            if not password and not key_filename:
                try:
                    # 先尝试标准连接（某些服务器可能使用默认密钥）
                    self.client.connect(**connect_kwargs)
                except (paramiko.AuthenticationException, paramiko.SSHException):
                    # 如果标准连接失败，尝试 "none" 认证
                    transport = paramiko.Transport((host, port))
                    transport.start_client()
                    transport.auth_none(username)
                    self.client._transport = transport
            else:
                self.client.connect(**connect_kwargs)
            
            self.host = host
            self.port = port
            self.username = username
            self.connected = True
            
            # 测试连接
            transport = self.client.get_transport()
            if transport:
                transport.set_keepalive(60)
            
            return {
                "status": "success",
                "msg": f"已连接到 {username}@{host}:{port}",
                "host": host,
                "port": port,
                "username": username,
            }
        
        except paramiko.AuthenticationException:
            return {"status": "error", "msg": f"认证失败: 用户名或密码/密钥错误"}
        except paramiko.SSHException as e:
            return {"status": "error", "msg": f"SSH 连接错误: {str(e)}"}
        except Exception as e:
            return {"status": "error", "msg": f"连接失败: {str(e)}"}
    
    def execute_and_return(self, command: str, timeout: int = 60, 
                           get_pty: bool = False) -> CommandResult:
        """阻塞模式执行命令，返回完整结果
        
        适用于简单查询（df -h, ps aux, ls 等）
        
        Args:
            command: 要执行的命令
            timeout: 超时时间（秒）
            get_pty: 是否分配伪终端
        
        Returns:
            CommandResult 对象
        """
        if not self.connected or not self.client:
            return CommandResult(
                exit_code=-1,
                stdout="",
                stderr="未连接到远程服务器",
                timed_out=False
            )
        
        try:
            stdin, stdout, stderr = self.client.exec_command(
                command, 
                timeout=timeout,
                get_pty=get_pty
            )
            
            # 读取输出
            stdout_text = stdout.read().decode('utf-8', errors='replace')
            stderr_text = stderr.read().decode('utf-8', errors='replace')
            exit_code = stdout.channel.recv_exit_status()
            
            return CommandResult(
                exit_code=exit_code,
                stdout=stdout_text,
                stderr=stderr_text,
                timed_out=False
            )
        
        except Exception as e:
            return CommandResult(
                exit_code=-1,
                stdout="",
                stderr=f"执行失败: {str(e)}",
                timed_out=False
            )
    
    def execute_and_forget(self, command: str) -> Dict[str, Any]:
        """执行命令但不等待结果（fire-and-forget）
        
        适用于不需要输出的后台任务
        """
        if not self.connected or not self.client:
            return {"status": "error", "msg": "未连接到远程服务器"}
        
        try:
            # 使用 nohup 确保命令在后台运行
            bg_command = f"nohup {command} > /dev/null 2>&1 &"
            stdin, stdout, stderr = self.client.exec_command(bg_command, timeout=5)
            stdout.read()  # 确保命令已发送
            return {"status": "success", "msg": f"命令已后台执行: {command}"}
        except Exception as e:
            return {"status": "error", "msg": f"执行失败: {str(e)}"}
    
    def start_streaming(self, command: str, save_to_file: Optional[str] = None,
                        get_pty: bool = True) -> Dict[str, Any]:
        """启动流式执行模式
        
        适用于需要实时输出的命令（tail -f, watch, sudo 等）
        
        Args:
            command: 要执行的命令
            save_to_file: 可选，将输出持久化到文件
            get_pty: 是否分配伪终端（交互式命令需要）
        
        Returns:
            包含 session_id 的字典，用于后续读取输出
        """
        if not self.connected or not self.client:
            return {"status": "error", "msg": "未连接到远程服务器"}
        
        self._session_counter += 1
        session_id = f"stream_{self._session_counter}_{int(time.time())}"
        
        try:
            transport = self.client.get_transport()
            if not transport:
                return {"status": "error", "msg": "无法获取传输通道"}
            
            channel = transport.open_session()
            if get_pty:
                channel.get_pty()
            channel.exec_command(command)
            
            # 创建流式会话
            streaming = StreamingSession(
                session_id=session_id,
                channel=channel,
                thread=None,  # 稍后设置
                output_file=save_to_file
            )
            
            # 启动读取线程
            def read_output():
                try:
                    while not channel.exit_status_ready():
                        if channel.recv_ready():
                            data = channel.recv(4096).decode('utf-8', errors='replace')
                            if data:
                                streaming.append_output(data)
                        if channel.recv_stderr_ready():
                            data = channel.recv_stderr(4096).decode('utf-8', errors='replace')
                            if data:
                                streaming.append_error(data)
                        time.sleep(0.1)  # 避免 CPU 占用过高
                    
                    # 读取剩余数据
                    while channel.recv_ready():
                        data = channel.recv(4096).decode('utf-8', errors='replace')
                        if data:
                            streaming.append_output(data)
                    while channel.recv_stderr_ready():
                        data = channel.recv_stderr(4096).decode('utf-8', errors='replace')
                        if data:
                            streaming.append_error(data)
                    
                    streaming.exit_code = channel.recv_exit_status()
                except Exception as e:
                    streaming.append_error(f"读取错误: {str(e)}")
                finally:
                    streaming.is_running = False
                    try:
                        channel.close()
                    except Exception:
                        pass
            
            streaming.thread = threading.Thread(target=read_output, daemon=True)
            streaming.thread.start()
            
            with self.lock:
                self.streaming_sessions[session_id] = streaming
            
            return {
                "status": "success",
                "session_id": session_id,
                "msg": f"流式会话已启动，使用 session_id={session_id} 读取输出",
                "command": command,
            }
        
        except Exception as e:
            return {"status": "error", "msg": f"启动流式会话失败: {str(e)}"}
    
    def read_output(self, session_id: str, lines: int = 0, 
                    since_marker: Optional[str] = None) -> Dict[str, Any]:
        """读取流式会话的缓冲输出
        
        Args:
            session_id: 会话 ID
            lines: 返回最后 N 行（0 表示全部）
            since_marker: 返回从指定标记之后的输出
        
        Returns:
            包含输出内容的字典
        """
        with self.lock:
            if session_id not in self.streaming_sessions:
                return {"status": "error", "msg": f"会话 {session_id} 不存在"}
            
            session = self.streaming_sessions[session_id]
        
        if since_marker:
            output = session.get_output_since(since_marker)
        elif lines > 0:
            output = session.get_recent_output(lines)
        else:
            output = session.get_full_output()
        
        return {
            "status": "success",
            "session_id": session_id,
            "is_running": session.is_running,
            "exit_code": session.exit_code,
            "output": output,
            "error": session.get_full_error(),
        }
    
    def send_input(self, session_id: str, text: str) -> Dict[str, Any]:
        """向流式会话发送输入（用于交互式命令）
        
        Args:
            session_id: 会话 ID
            text: 要发送的文本（会自动添加换行符）
        
        Returns:
            操作结果
        """
        with self.lock:
            if session_id not in self.streaming_sessions:
                return {"status": "error", "msg": f"会话 {session_id} 不存在"}
            
            session = self.streaming_sessions[session_id]
        
        if not session.is_running:
            return {"status": "error", "msg": "会话已结束"}
        
        try:
            session.channel.send(text + "\n")
            return {"status": "success", "msg": f"已发送输入: {text[:50]}..."}
        except Exception as e:
            return {"status": "error", "msg": f"发送输入失败: {str(e)}"}
    
    def stop_streaming(self, session_id: str, _internal: bool = False) -> Dict[str, Any]:
        """停止流式会话
        
        Args:
            session_id: 会话 ID
            _internal: 内部调用标记（由 close() 调用时传入，跳过锁以避免死锁）
        
        Returns:
            包含最终输出的字典
        """
        if not _internal:
            with self.lock:
                if session_id not in self.streaming_sessions:
                    return {"status": "error", "msg": f"会话 {session_id} 不存在"}
                session = self.streaming_sessions[session_id]
        else:
            if session_id not in self.streaming_sessions:
                return {"status": "error", "msg": f"会话 {session_id} 不存在"}
            session = self.streaming_sessions[session_id]
        
        if not session.is_running:
            return {
                "status": "success",
                "msg": "会话已停止",
                "output": session.get_full_output(),
                "exit_code": session.exit_code,
            }
        
        try:
            session.channel.close()
            session.thread.join(timeout=3)
            session.is_running = False
            
            return {
                "status": "success",
                "msg": "会话已停止",
                "output": session.get_full_output(),
                "error": session.get_full_error(),
                "exit_code": session.exit_code,
            }
        except Exception as e:
            return {"status": "error", "msg": f"停止会话失败: {str(e)}"}
    
    def list_streaming_sessions(self) -> Dict[str, Any]:
        """列出所有活跃的流式会话"""
        with self.lock:
            sessions = []
            for sid, session in self.streaming_sessions.items():
                sessions.append({
                    "session_id": sid,
                    "is_running": session.is_running,
                    "exit_code": session.exit_code,
                    "output_length": len(session.get_full_output()),
                })
        
        return {
            "status": "success",
            "count": len(sessions),
            "sessions": sessions,
        }
    
    def close(self) -> Dict[str, Any]:
        """关闭所有连接和会话"""
        try:
            # 停止所有流式会话（在锁内通过 _internal 标记避免死锁）
            with self.lock:
                for session_id in list(self.streaming_sessions.keys()):
                    self.stop_streaming(session_id, _internal=True)
                self.streaming_sessions.clear()
            
            # 关闭 SSH 连接（在锁外操作，避免 transport 关闭阻塞时持锁）
            if self.client:
                try:
                    self.client.close()
                except Exception:
                    pass
                self.client = None
            
            self.connected = False
            return {"status": "success", "msg": "连接已关闭"}
        
        except Exception as e:
            return {"status": "error", "msg": f"关闭连接失败: {str(e)}"}


# 全局会话管理器
_sessions: Dict[str, SSHSession] = {}


def _get_session(session_id: Optional[str] = None, 
                  streaming_id: Optional[str] = None) -> Optional[SSHSession]:
    """获取指定会话，或返回默认会话
    
    如果提供了 streaming_id，会搜索所有 SSH 会话中包含该流式会话的那个。
    """
    if streaming_id:
        # 搜索包含该流式会话的 SSH 会话
        for sess in _sessions.values():
            if streaming_id in sess.streaming_sessions:
                return sess
        return None
    if session_id:
        return _sessions.get(session_id)
    if _sessions:
        return next(iter(_sessions.values()))
    return None


def ssh_connect(host: str, port: int = 22, username: str = "root",
                password: Optional[str] = None, key_filename: Optional[str] = None,
                session_id: Optional[str] = None, timeout: int = 10) -> Dict[str, Any]:
    """连接到远程 SSH 服务器
    
    Args:
        host: 主机地址
        port: SSH 端口
        username: 用户名
        password: 密码
        key_filename: 私钥文件路径
        session_id: 会话 ID（可选，默认自动生成）
        timeout: 连接超时
    
    Returns:
        包含连接状态的字典
    """
    if not session_id:
        session_id = f"ssh_{host}_{port}_{username}"
    
    session = SSHSession()
    result = session.connect(host, port, username, password, key_filename, timeout)
    
    if result["status"] == "success":
        _sessions[session_id] = session
        result["session_id"] = session_id
    
    return result


def ssh_execute(command: str, session_id: Optional[str] = None, 
                timeout: int = 60, mode: str = "blocking") -> Dict[str, Any]:
    """在远程服务器上执行命令
    
    Args:
        command: 要执行的命令
        session_id: 会话 ID（使用最近的会话如果不指定）
        timeout: 超时时间
        mode: 执行模式
            - "blocking": 阻塞模式，返回完整结果
            - "streaming": 流式模式，启动后台流式输出
    
    Returns:
        包含执行结果的字典
    """
    session = _get_session(session_id)
    if not session:
        return {"status": "error", "msg": "没有可用的 SSH 会话，请先调用 ssh_connect"}
    
    if mode == "blocking":
        result = session.execute_and_return(command, timeout)
        return {
            "status": "success" if result.exit_code == 0 else "error",
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": result.timed_out,
        }
    else:
        return session.start_streaming(command)


def ssh_read_output(session_id: str, lines: int = 0, 
                    since_marker: Optional[str] = None) -> Dict[str, Any]:
    """读取流式会话的缓冲输出
    
    Args:
        session_id: 流式会话 ID（来自 ssh_execute 的 stream 返回）
        lines: 返回最后 N 行（0 表示全部）
        since_marker: 返回从指定标记之后的输出
    
    Returns:
        包含输出内容的字典
    """
    session = _get_session(streaming_id=session_id)
    if not session:
        return {"status": "error", "msg": f"没有找到包含流式会话 {session_id} 的 SSH 连接"}
    
    return session.read_output(session_id, lines, since_marker)


def ssh_send_input(session_id: str, text: str) -> Dict[str, Any]:
    """向流式会话发送输入
    
    Args:
        session_id: 流式会话 ID
        text: 要发送的文本
    
    Returns:
        操作结果
    """
    session = _get_session(streaming_id=session_id)
    if not session:
        return {"status": "error", "msg": f"没有找到包含流式会话 {session_id} 的 SSH 连接"}
    
    return session.send_input(session_id, text)


def ssh_stop_streaming(session_id: str) -> Dict[str, Any]:
    """停止流式会话"""
    session = _get_session(streaming_id=session_id)
    if not session:
        return {"status": "error", "msg": f"没有找到包含流式会话 {session_id} 的 SSH 连接"}
    
    return session.stop_streaming(session_id)


def ssh_list_sessions() -> Dict[str, Any]:
    """列出所有活跃的 SSH 会话"""
    result = {
        "status": "success",
        "active_sessions": [],
        "streaming_sessions": [],
    }
    
    for sid, session in _sessions.items():
        result["active_sessions"].append({
            "session_id": sid,
            "host": session.host,
            "port": session.port,
            "username": session.username,
            "connected": session.connected,
        })
    
    # 获取流式会话信息
    for session in _sessions.values():
        stream_info = session.list_streaming_sessions()
        result["streaming_sessions"].extend(stream_info.get("sessions", []))
    
    return result


def ssh_close(session_id: Optional[str] = None) -> Dict[str, Any]:
    """关闭 SSH 连接
    
    Args:
        session_id: 要关闭的会话 ID（关闭所有会话如果不指定）
    """
    if session_id:
        session = _sessions.pop(session_id, None)
        if session:
            return session.close()
        return {"status": "error", "msg": f"会话 {session_id} 不存在"}
    
    # 关闭所有会话
    results = []
    for sid, session in list(_sessions.items()):
        results.append(session.close())
    _sessions.clear()
    
    return {
        "status": "success",
        "msg": f"已关闭 {len(results)} 个连接",
        "results": results,
    }


# 便捷函数
def quick_execute(host: str, command: str, username: str = "root",
                  password: Optional[str] = None, port: int = 22) -> str:
    """快速执行单个命令（阻塞模式）
    
    Args:
        host: 主机地址
        command: 要执行的命令
        username: 用户名
        password: 密码
        port: SSH 端口
    
    Returns:
        命令输出字符串
    """
    session_id = f"quick_{host}_{port}"
    result = ssh_connect(host, port, username, password, session_id=session_id)
    if result["status"] != "success":
        return f"[Error] {result['msg']}"
    
    result = ssh_execute(command, session_id=session_id)
    ssh_close(session_id)
    
    if result["status"] == "success":
        return result.get("stdout", "")
    else:
        return f"[Error] {result.get('stderr', result.get('msg', 'Unknown error'))}"


if __name__ == "__main__":
    # 测试代码
    print("SSH Tool 模块加载成功")
    print(f"Paramiko 版本: {paramiko.__version__ if paramiko else '未安装'}")
