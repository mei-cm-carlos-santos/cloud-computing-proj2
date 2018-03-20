<?php
try {
    require_once("util.php");
    addCors();
    
    $username = getInputParam("username");

    $sql = "Select count(*) from users where username = ?";

    $stmt = db()->prepare($sql);
    $stmt->bind_param("s", $username);
    $stmt->execute();

    $stmt->bind_result($total);

    $stmt->fetch();

    if ($total == 0) {
        header('OK', true, 200);
        header('Content-Type: application/json');
        echo json_encode(['msg' => 'Username does not exist on database']);
    } else {
        header('Forbidden', true, 403);
        header('Content-Type: application/json');
        echo json_encode(['msg' => 'Username already exists']);
    }
    $stmt->close();
} catch (Exception $e) {
    header('Unauthorized', true, 401);
    echo 'Something went wrong';
}
