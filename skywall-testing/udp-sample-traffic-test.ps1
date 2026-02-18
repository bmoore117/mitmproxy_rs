$udp = New-Object System.Net.Sockets.UdpClient
$udp.Connect("1.1.1.1", 51820)   # blocked UDP port
1..10 | ForEach-Object {
  $msg = "udp-test-$_"
  $bytes = [System.Text.Encoding]::ASCII.GetBytes($msg)
  [void]$udp.Send($bytes, $bytes.Length)
  Start-Sleep -Milliseconds 200
}
$udp.Close()