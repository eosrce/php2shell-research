<?php /* _r41prime2.php */
$pad=(int)($_GET["pad"]??0);
$mb=(int)($_GET["mb"]??0);
$keep=array();
for($i=0;$i<$pad;$i++){ $keep[]=str_repeat("Z",4080); }
if($mb>0){ $keep[]=str_repeat("B",$mb*1048576); }
session_start();
echo "OK";
