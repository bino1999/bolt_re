<?php
include 'config.php';

$fname = $_POST["fname"];
$lname = $_POST["lname"];
$address = $_POST["address"];
$city = $_POST["city"];
$pin = $_POST["pin"];
$email = $_POST["email"];
$rawPwd = $_POST["pwd"];

// Hash the password
$hashedPwd = password_hash($rawPwd, PASSWORD_DEFAULT);

try {
    // Prepared statement
    $stmt = $mysqli->prepare("INSERT INTO users (fname, lname, address, city, pin, email, password) VALUES (?, ?, ?, ?, ?, ?, ?)");

    // Check if the statement was prepared successfully
    if ($stmt === false) {
        throw new Exception("Database error. Please try again later.");
    }

    // Bind parameters
    $stmt->bind_param("ssssiss", $fname, $lname, $address, $city, $pin, $email, $hashedPwd);

    // Execute the statement
    if ($stmt->execute()) {
        echo 'Data inserted';
        echo '<br/>';
    } else {
        throw new Exception("Error inserting data into the database.");
    }

    // Close the statement
    $stmt->close();

    // Close the database connection
    $mysqli->close();

    header("location:login.php");
    exit(); // Ensure that no further code is executed
} catch (Exception $e) {
    // Log the exception or display a generic error message
    echo "An error occurred: " . $e->getMessage();
}
?>
