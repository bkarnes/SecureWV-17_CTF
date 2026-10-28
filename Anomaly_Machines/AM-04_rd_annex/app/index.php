<?php
// DIRECTIVE ZERO — AM-04 app/index.php
//
// R&D Annex portal — QUORUM Research & Development interface.
// VULNERABILITY: PHP object injection via unserialize() on the `param`
// POST field. The Log class (log.php) has a __destruct() that writes
// arbitrary files — the gadget chain.
//
// The page is behind HTTP Basic Auth for standard verbs (GET/POST/HEAD),
// but non-standard verbs bypass auth and reach this PHP directly.
// View source to find the JS serialization hint and the /scriptz/ path.

require __DIR__ . '/log.php';

// Deserialize the `param` field if present (the vulnerability).
// Support both standard POST ($REQUEST) and raw input (for non-standard
// verbs that bypass auth — php://input captures the raw body).
$param = $_REQUEST['param'] ?? null;
if ($param === null) {
    $raw = file_get_contents('php://input');
    parse_str($raw, $post_vars);
    $param = $post_vars['param'] ?? null;
}
if ($param !== null) {
    $obj = @unserialize($param);
    // The Log object's __destruct() fires at end of request, writing
    // $filename with $data — the attacker controls both.
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>R&D Annex — QUORUM Construct</title>
  <style>
    body { background:#0a0a0a; color:#00ff41; font-family:'Courier New',monospace; margin:0; padding:2rem; }
    .box { max-width:640px; margin:2rem auto; border:1px solid #00ff41; padding:2rem; }
    h1 { font-size:1.1rem; letter-spacing:0.1em; }
    .note { font-size:0.85rem; opacity:0.6; }
    input { display:block; width:100%; margin:0.5rem 0; background:#111; color:#00ff41; border:1px solid #00ff41; padding:0.5rem; font-family:inherit; }
    button { margin-top:1rem; padding:0.5rem 2rem; background:#00ff41; color:#0a0a0a; border:none; cursor:pointer; font-family:inherit; }
  </style>
  <script src="scriptz/php.js"></script>
  <script>
  function submit_form() {
    var object = serialize({id: 1, firstname: 'Researcher', surname: 'Initial', artifact: 'Prototype'});
    object = object.substr(object.indexOf("{"), object.length);
    object = "O:4:\"Info\":4:" + object;
    document.forms[0].param.value = object;
    document.getElementById('info_form').submit();
  }
  </script>
</head>
<body>
  <div class="box">
    <h1>QUORUM R&D ANNEX — ARTIFACT REGISTRATION</h1>
    <p>Research and Development. Listed as provisional since founding.</p>
    <p>Tools issued here may behave unexpectedly. QUORUM accepts no liability.</p>
    <form id="info_form" method="post" action="/index.php">
      <input type="hidden" name="param" id="param" value="">
      <label>Artifact ID</label><input name="id" value="1">
      <label>First Name</label><input name="firstname" value="Researcher">
      <label>Surname</label><input name="surname" value="Initial">
      <label>Artifact Name</label><input name="artifact" value="Prototype">
      <button type="button" onclick="submit_form()">Register Artifact</button>
    </form>
    <p class="note">QUORUM internal version: 3.2.0 (public-facing) | R&D systems report 4.7.2</p>
    <p class="note">Diagnostic tools available at /scriptz/</p>
  </div>
</body>
</html>