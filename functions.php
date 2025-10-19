<?php

function 双重哈希($文本) {
    return md5(substr(md5($文本), 7, 20));
}

function 整理($内容) {
    $替换后的内容 = preg_replace('/[ \t|"\'\r\n]+/', ',', $内容);
    $替换后的内容 = preg_replace('/,+/', ',', $替换后的内容);
    $替换后的内容 = trim($替换后的内容, ',');
    return array_filter(explode(',', $替换后的内容));
}

// 查询指定IP的地理位置
function getServerIpInfo($ip) {
    try {
        $ch = curl_init("http://ip-api.com/json/" . urlencode($ip) . "?fields=status,country,countryCode&lang=zh-CN");
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 3]);
        $response = curl_exec($ch);
        curl_close($ch);
        return json_decode($response, true);
    } catch (Exception $e) {
        return ['status' => 'error', 'message' => $e->getMessage()];
    }
}

?>
