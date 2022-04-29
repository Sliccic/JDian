let headers = $request.headers

let oriHost = /\/\/([\d\.a-zA-Z0-9:\-]*\/?)/.exec（$request.url）[1]
让主机= oriHost
if (oriHost[oriHost.length - 1] == '/') {
  host = oriHost.substring(0, oriHost.length - 1)
}

标题['host'] = 主机

$done（{
  url: $request.url.replace(oriHost, '185.163.127.36:443/').replace('http://', 'https://'),标题，
}）
