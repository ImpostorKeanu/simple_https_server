var reloadFlag = false;
var interval;
function reloadWait () {
    interval = setInterval(function(){
        if(reloadFlag){
            reloadFlag=false;
            document.location.reload();
        }
    })
}
reloadWait();

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
	var submit = document.getElementsByName("submit");
	var input = document.querySelector('input[type="file"]');
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

		// Create new form data
		var formData = new FormData();

		formData.append("file", new Blob([data],{type: "text/base64"}), file.name);

		// Make the HTTP request
		var xhttp = new XMLHttpRequest();
        xhttp.timeout=30000;
		xhttp.open("POST", "/", true);
		xhttp.send(formData);
        reloadFlag=true;
	}
	reader.readAsBinaryString(file);
    return false;
}

// For downloads
function downloader(fname,decode){
    if(decode == undefined){ decode = false; }
	var xhttp = new XMLHttpRequest();
	xhttp.open("GET",fname,true);
    xhttp.timeout=30000;
	xhttp.onreadystatechange = function() {
		if(this.readyState == 4 && this.status == 200){
			var blob;
            if(decode){
                blob = decode64(this.responseText, 2);
            } else {
                blob = new Blob([this.responseText], {type:'text/base64'});
            }
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
