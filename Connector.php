<?php  

class Connector {
	private $socket;
	private $host;
	private $port;
	private $user;
	private $password;
	private $dbname;

	public function __construct($host = '127.0.0.1', $user='root', $password='t', $dbname='t' ,$port='3306')
	{
		$this->host = $host;
		$this->user = $user;
		$this->password = $password;
		$this->dbname = $dbname;
		$this->port = $port;
		$this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
	}

	public function connect(){
		if (!$this->socket) {
			throw new Exception("Socket yaratilishida xatolik: ".  socket_strerror(socket_last_error($this->socket)) );
		}

		if (!socket_connect($this->socket, $this->host,$this->port)) {
			throw new Exception("Ulanishdagi xatolik: ". socket_strerror(socket_last_error($this->socket)));
		}

		print_r("Mysqlga Ulandi \n");

		$handshake = socket_read($this->socket, 2048);
		$salt = $this->salt($handshake);


		$auth = $this->authPacket($salt);
		socket_write($this->socket,$auth);


		$response = socket_read($this->socket,2048);

		if (strpos(bin2hex($response), '00') == false) {
			print_r("Auth da hatolil: ". bin2hex($response));
		}

		print_r("server Javobi:". bin2hex($response). "\n");
	}

	private function salt($handshake) {
	    $p1 = substr($handshake, 15, 8);
	    $p2 = substr($handshake, 27, 12);
	    return $p1 . $p2;
	}

	public function authPacket($salt) {
	    $passHash = sha1($this->password, true);
	    $doubleHash = sha1($passHash, true);
	    $saltHash = sha1($salt . $doubleHash, true);
	    $finalHash = $passHash ^ $saltHash;

	    $clientFlags = 0x00002085; // Oddiy flaglar
	    $maxPacketSize = 0x1000000; // Maksimal paket uzunligi
	    $charset = 0x21; // UTF-8 charset

	    $payload = pack("V", $clientFlags);
	    $payload .= pack("V", $maxPacketSize);
	    $payload .= chr($charset) . str_repeat(chr(0), 23);
	    $payload .= $this->user . chr(0);
	    $payload .= chr(strlen($finalHash)) . $finalHash;
	    $payload .= $this->dbname . chr(0);

	    $packetLength = pack("V", strlen($payload));
	    $packet = substr($packetLength, 0, 3) . chr(1) . $payload;

	    return $packet;
	}


	public function query($sqlQuery) {
	    $queryLen = strlen($sqlQuery);
	    $packetHeader = pack("V", $queryLen) . chr(0);
	    $packet = substr($packetHeader, 0, 3) . chr(3) . $sqlQuery; 

	    if (!socket_write($this->socket, $packet, strlen($packet))) {
	        throw new Exception("Socketga yozishda xatolik: " . socket_strerror(socket_last_error($this->socket)));
	    }

	    $res = socket_read($this->socket, 2048);
	    if ($res === false) {
	        throw new Exception("Socketdan o'qishda xatolik: " . socket_strerror(socket_last_error($this->socket)));
	    }
	    return $res;
	}

	public function close(){
		socket_close($this->socket);
	}
}


$db = new Connector('host','username','pass','dbname','port');
$db->connect();
