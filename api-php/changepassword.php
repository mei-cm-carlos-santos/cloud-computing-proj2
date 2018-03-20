<?php
// ONLY AUTHENTICATED USERS CAN ACCESS THIS FILE
try {
    require_once("util.php");
    addCors();

    // Only checks for token when requested method = "real" method
    // if methos = OPTION, Just return OK
    if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
         header('OK', true, 200);
    } else {
        $userInfo = validateToken();
        if ($userInfo) {
            $oldpassword = getInputParam("oldpassword");
            $newpassword = getInputParam("newpassword");

            $sql = "select passwordhash, _id from users where username = ?";

            $stmt = db()->prepare($sql);
            $stmt->bind_param("s", $userInfo->username);
            $stmt->execute();

            $stmt->bind_result($hashFromDb, $userId);

            $stmt->fetch();

            if (password_verify($oldpassword, $hashFromDb) && ($userId == $userInfo->userID)) {
                $stmt->close();
                
                $passwordhash = password_hash($newpassword, PASSWORD_DEFAULT);

                $sql = "Update users set passwordhash = ? where username = ?";

                $stmt = db()->prepare($sql);
                $stmt->bind_param("ss", $passwordhash, $userInfo->username);
                $stmt->execute();

                if ($stmt->affected_rows == 1) {
                    header('OK', true, 200);
                    header('Content-Type: application/json');
                    echo json_encode(['msg' => 'User password has changed']);
                } else {
                    header('Unauthorized', true, 401);
                }
            } else {
                header('Unauthorized', true, 401);
            }
            $stmt->close();
        } else {
            header('Unauthorized', true, 401);
        }
    }
} catch (Exception $e) {
    header('Unauthorized', true, 401);
}
