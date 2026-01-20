<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::delete('/user', function (Request $request) {
    $request->user()->delete();
    return response()->json(['message' => 'User deleted successfully']);
})->middleware('auth:sanctum');

Route::post('/login', function (Request $request) {
    $credentials = $request->validate([
        'email' => 'required|email',
        'password' => 'required',
    ]);

    if (!Auth::attempt($credentials)) {
        return response()->json(['message' => 'Unauthorized'], 401);
    }

    $token = $request->user()->createToken('auth-token');

    return response()->json([
        'token' => $token->plainTextToken,
        'user' => $request->user(),
    ]);
});

Route::post('/register', function (Request $request) {
    $data = $request->validate([
        'name' => 'required|string|max:255',
        'email' => 'required|string|email|max:255|unique:users',
        'password' => 'required|string|min:6',
    ]);

    $user = \App\Models\User::create([
        'name' => $data['name'],
        'email' => $data['email'],
        'password' => \Illuminate\Support\Facades\Hash::make($data['password']),
    ]);

    $token = $user->createToken('auth-token');

    return response()->json([
        'token' => $token->plainTextToken,
        'user' => $user,
    ]);
});
