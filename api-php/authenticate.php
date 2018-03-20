<?php
try {
    require_once("util.php");
    addCors();
    
    $username = getInputParam("username");
    $password = getInputParam("password");

    $sql = "select passwordhash, name, email, _id from users where username = ?";

    $stmt = db()->prepare($sql);
    $stmt->bind_param("s", $username);
    $stmt->execute();

    $stmt->bind_result($hashFromDb, $name, $email, $userId);

    $stmt->fetch();

    if (password_verify($password, $hashFromDb)) {
        header('OK', true, 200);
        header('Content-Type: application/json');
        echo json_encode(createToken($userId, $username, $name, $email));
    } else {
        header('Forbidden', true, 403);
        header('Content-Type: application/json');
        echo json_encode(['msg' => 'Unauthorized']);
    }
    $stmt->close();
} catch (Exception $e) {
    header('Unauthorized', true, 401);
    echo 'Something went wrong';
}
