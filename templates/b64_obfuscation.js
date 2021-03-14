function contentToBuffer(b64){
	var len = b64.length;
	bytes = new Uint8Array(len);
	for(var i=0; i<len; i++){
		bytes[i] = b64.charCodeAt(i);
	}
	return bytes.buffer;
}

function decode64(b64,iterations){
	if(!iterations) {iterations = 1};
	for(;iterations>0;iterations--){
		b64 = window.atob(b64);
	}
	buff = contentToBuffer(b64);
	var blob = new Blob([buff], {type: 'octet/stream'});
	return blob;
}


// For uploads
function encoder(iterations){
	var form = document.getElementsByName("form");
	var input = document.querySelector('input[type="file"]')
	var file = input.files[0];
	if(!iterations) {iterations = 1};
	var reader = new FileReader();
	var data;
	reader.onloadend = function() {

		// Process the file upload
		var data = reader.result;
		for(;iterations>0;iterations--){
			data = window.btoa(data);
		}

        console.log(data);

		// Create new form data
		var formData = new FormData();

		formData.append("file", new Blob([data],{type: "text/base64"}), file.name);

        console.log(formData);

		// Make the HTTP request
		var xhttp = new XMLHttpRequest();
		xhttp.open("POST", "/", true);
		xhttp.send(formData);
        document.location.reload();
	}
	reader.readAsBinaryString(file);
    return false;
}

// For downloads
function decoder(fname){
    console.log('decoder called');
	var xhttp = new XMLHttpRequest();
	xhttp.open("GET",fname,true);
	xhttp.onreadystatechange = function() {
		if(this.readyState == 4 && this.status == 200){
			var blob = decode64(this.responseText, 2);
			var a = document.createElement('a');
			var u = window.URL.createObjectURL(blob);
			document.body.appendChild(a);
			a.style = 'display:none';
			a.href = u;
			a.download = fname;
			a.click();
			window.URL.revokeObjectURL(u);
		}
	}
	xhttp.send();
}
