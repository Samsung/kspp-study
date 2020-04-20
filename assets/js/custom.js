(function() {
    function update_sidebar(html, path) {
	// discard the current active menus
	var old = document.querySelectorAll("a[class='active']");
	old.forEach((e) => e.removeAttribute("class", "active"));

	// highlight section/subsection
	[path, html].forEach((href) => {
	    var cur = document.querySelector("a[href='" + href + "']");
	    if (cur)
		cur.setAttribute("class", "active");
	});
    }

    function update_sidebar_onclick(event) {
	var path = event.target.href;

	// clean up http://
	var pos = path.lastIndexOf("/");
	if (pos != -1)
	    path = path.slice(pos + 1);

	var html = path;
	pos = path.indexOf("#");
	if (pos != -1)
	    html = path.slice(0, pos);

	update_sidebar(html, path);
    }

    function update_sidebar_onready() {
	var html = document.location.pathname.slice(1);
	var path = html;
	if (document.location.hash !== '')
	    path += document.location.hash;
	update_sidebar(html, path);
    }

    
    document.addEventListener('click', update_sidebar_onclick);
    document.addEventListener('DOMContentLoaded', update_sidebar_onready);

})();
