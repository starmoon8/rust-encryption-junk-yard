<?php
if (empty($_POST["field2"])) {
   die( "<h1>" . '<a href="index.html">Post empty- Click here to return</a>'. "<h1>"); } if(isset($_POST['field2'])) {
$data =  '<table>' . '<td class="reply">' . '<div class="message">' . '<b>'  . htmlentities($_POST["field2"], ENT_QUOTES | ENT_IGNORE, "UTF-8") . '</b>' .'</td>' . '</tr>'. '</table>'. '</div>';
$ret = file_put_contents('index.html', $data, FILE_APPEND | LOCK_EX);
if($ret === false) { die('There was an error writing this file');
} else { header("Location: ./");
}
}
 
