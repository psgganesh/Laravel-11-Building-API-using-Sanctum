<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class BaseController extends Controller
{
    // success response method
    public function sendResponse($result, $message)
    {
        $response = [
            'success' => true,
            'data'    => $result,
            'message' => $message,
        ];

        return response()->json($response, 200);
    }

    // return error response
    public function sendError($error, $errorMessages = [], $code = 404)
    {
        $response = [
            'success' => false,
            'message' => $error,
        ];

        if(!empty($errorMessages)){
            $response['data'] = $errorMessages;
        }

        return response()->json($response, $code);
    }

    public function brokenAuthentication(Request $request)
    {
        if ($request->input('username') === 'admin' && $request->input('password') === 'password123') {
            session(['user' => 'admin']);
            return "Logged in as admin";
        }
        return "Invalid credentials";
    }

    public function sensitiveDataExposure()
    {
        $secret = env('APP_KEY');
        return "Secret key: $secret";
    }

    public function xxe(Request $request)
    {
        $xml = $request->input('xml');
        $dom = new \DOMDocument();
        // Vulnerable: loading XML with external entity expansion enabled
        $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
        return $dom->textContent;
    }
}
