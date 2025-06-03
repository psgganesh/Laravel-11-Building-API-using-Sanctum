<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;

abstract class Controller
{
    // 1. Injection (SQL Injection)
    public function sqlInjection(Request $request)
    {
        $username = $request->input('username');
        // Vulnerable: unsanitized input in raw query
        $user = DB::select("SELECT * FROM users WHERE username = '$username'");
        return response()->json($user);
    }

    // 2. Broken Authentication (using hardcoded credentials)
    public function brokenAuthentication(Request $request)
    {
        // Vulnerable: hardcoded credentials
        if ($request->input('username') === 'admin' && $request->input('password') === 'password123') {
            session(['user' => 'admin']);
            return "Logged in as admin";
        }
        return "Invalid credentials";
    }

    // 3. Sensitive Data Exposure (insecurely echoing secrets)
    public function sensitiveDataExposure()
    {
        // Vulnerable: printing sensitive data
        $secret = env('APP_KEY');
        return "Secret key: $secret";
    }

    // 4. XML External Entities (XXE) (PHP DOMDocument with external entities)
    public function xxe(Request $request)
    {
        $xml = $request->input('xml');
        $dom = new \DOMDocument();
        // Vulnerable: loading XML with external entity expansion enabled
        $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
        return $dom->textContent;
    }

    // 5. Broken Access Control (no auth check before accessing user data)
    public function brokenAccessControl(Request $request)
    {
        $userId = $request->input('user_id');
        // Vulnerable: no authentication or authorization check
        $user = DB::table('users')->where('id', $userId)->first();
        return response()->json($user);
    }

    // 6. Security Misconfiguration (debug mode enabled, exposing PHP info)
    public function securityMisconfiguration()
    {
        // Vulnerable: exposing phpinfo
        ob_start();
        phpinfo();
        $info = ob_get_clean();
        return $info;
    }

    // 7. Cross-Site Scripting (XSS)
    public function xss(Request $request)
    {
        $input = $request->input('q');
        // Vulnerable: outputting unsanitized user input in HTML
        return "<html><body>Search results for: $input</body></html>";
    }

    // 8. Insecure Deserialization (unserialize user data)
    public function insecureDeserialization(Request $request)
    {
        $data = $request->input('data');
        // Vulnerable: unserializing untrusted input
        $obj = unserialize($data);
        return response()->json($obj);
    }

    // 9. Using Components with Known Vulnerabilities (intentionally using old/vulnerable code, demo only)
    public function vulnerableComponent()
    {
        // Vulnerable: Demo of using eval to show arbitrary code execution via old/vulnerable code
        $code = "echo 'This is vulnerable';";
        eval($code);
    }

    // 10. Insufficient Logging & Monitoring (no logging of failures)
    public function insufficientLogging(Request $request)
    {
        $username = $request->input('username');
        $password = $request->input('password');
        // Vulnerable: failed login attempts are not logged
        if ($username === 'admin' && $password === 'password123') {
            return "Logged in";
        }
        return "Login failed";
    }
}
