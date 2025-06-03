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
