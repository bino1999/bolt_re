<?php

if (session_id() == '' || !isset($_SESSION)) {
    session_start();
}

include 'config.php';

// CSRF token validation
if (!isset($_SESSION['csrf_token']) || !isset($_POST['csrf_token']) || $_SESSION['csrf_token'] !== $_POST['csrf_token']) {
    // Invalid CSRF token
    handleInvalidToken();
}

$username = $_POST["username"];
$password = $_POST["pwd"];
$flag = 'true';


$stmt = $mysqli->prepare('SELECT id, email, password, fname, type FROM users WHERE email = ? ORDER BY id ASC');

// Check if the statement is prepared successfully
if ($stmt === false) {
    handleDatabaseError();
}

// Bind parameters
$stmt->bind_param('s', $username);

// Execute the statement
$result = $stmt->execute();

// Check if the execution was successful
if ($result === false) {
    handleDatabaseError();
}

// Bind the result variables
$stmt->bind_result($id, $email, $hashedPwd, $fname, $type);

// Fetch the result
while ($stmt->fetch()) {
    // Use password_verify for secure password comparison
    if (password_verify($password, $hashedPwd)) {
        // Successful login
        $_SESSION['username'] = $username;
        $_SESSION['type'] = $type;
        $_SESSION['id'] = $id;
        $_SESSION['fname'] = $fname;

        // Redirect to the index page
        header('location: index.php');
        exit();
    } else {
        // Invalid password
        if ($flag === 'true') {
            handleInvalidLogin();
            $flag = 'false';
        }
    }
}

// Close the statement
$stmt->close();

function handleInvalidToken() {
    // Invalid CSRF token
    echo '<h1>Invalid CSRF Token! Redirecting...</h1>';
    header('Refresh: 3; url=index.php');
    exit();
}

function handleInvalidLogin() {
    // Invalid password
    echo '<h1>Invalid Login! Redirecting...</h1>';
    header('Refresh: 3; url=index.php');
    exit();
}

function handleDatabaseError() {
    // Handle database error
    // Log the error, display a generic message to the user, and redirect
    echo '<h1>Internal Server Error! Redirecting...</h1>';
    error_log('Database Error: ' . $mysqli->error);
    header('Refresh: 3; url=index.php');
    exit();
}
?>
