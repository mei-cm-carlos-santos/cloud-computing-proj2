<?php
try {
    require_once("util.php");
    addCors();
    $name = getInputParam("name");
    $email = getInputParam("email");
    $username = getInputParam("username");
    $password = getInputParam("password");
    $id = getInputParam("id");

    $passwordhash = password_hash($password, PASSWORD_DEFAULT);

    $sql = "insert into users (_id, username, name, email, passwordhash) values (?, ?, ?, ?, ?)";

    $stmt = db()->prepare($sql);
    $stmt->bind_param("sssss", $id, $username, $name, $email, $passwordhash);
    $stmt->execute();

    if ($stmt->affected_rows == 1) {
        header('OK', true, 200);
        header('Content-Type: application/json');
        echo json_encode(createToken($id, $username, $name, $email));
    } else {
        header('Unauthorized', true, 401);
        echo 'Something went wrong';
    }
    $stmt->close();
} catch (Exception $e) {
    header('Unauthorized', true, 401);
    echo 'Something went wrong';
}
